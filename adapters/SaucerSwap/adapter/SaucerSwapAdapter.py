import os
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
import yaml
from adapters.common.config import get_project_root, load_project_env, configure_logging, resolve_from_root


@dataclass
class SaucerSwapConfig:
    network: str
    private_key_path: str
    api_base: str
    json_rpc_endpoints: List[str]
    contracts: Dict[str, str]
    abi_files: Dict[str, str]


class EndpointRotator:
    def __init__(self, endpoints: List[str]):
        if not endpoints:
            raise ValueError("At least one endpoint is required")
        self._endpoints = endpoints
        self._index = 0

    @property
    def current(self) -> str:
        return self._endpoints[self._index]

    def rotate(self) -> str:
        self._index = (self._index + 1) % len(self._endpoints)
        return self.current


class SaucerSwapAdapter:
    def __init__(self, config_path: str):
        project_root = get_project_root(__file__)
        load_project_env(project_root)
        configure_logging()
        self.logger = logging.getLogger(self.__class__.__name__)

        self.api_key = os.getenv("SAUCER_API")
        if not self.api_key:
            raise RuntimeError("SAUCER_API no configurada en .env")

        config_path_abs = resolve_from_root(project_root, config_path)
        with open(config_path_abs, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        hed = cfg["hedera"]
        ssw = cfg["saucerswap"]
        self.config = SaucerSwapConfig(
            network=hed["network"],
            private_key_path=(hed.get("wallet") or {})["private_key_path"],
            api_base=ssw["api_base"],
            json_rpc_endpoints=hed.get("json_rpc_endpoints", []),
            contracts=ssw.get("contracts", {}),
            abi_files=ssw.get("abi_files", {}),
        )

        # account_id desde keyfile
        expanded = os.path.expanduser(self.config.private_key_path)
        with open(expanded, "r", encoding="utf-8") as f:
            key_json = json.load(f)
        self.account_id = key_json["account_id"]

        # Derivar dirección EVM desde clave privada (ECDSA secp256k1)
        self._private_key_hex = self._extract_private_key_hex(key_json)
        self.evm_address = self._derive_evm_address_from_private_key(self._private_key_hex)

        self.rpc = EndpointRotator(self.config.json_rpc_endpoints or ["https://mainnet.hashio.io/api"])  # fallback mínimo
        self.logger.info("SaucerSwapAdapter inicializado (network=%s, account_id=%s, evm=%s)", self.config.network, self.account_id, self.evm_address)

        # ABI del router (para decodificar errores)
        self._router_abi: Optional[List[Dict[str, Any]]] = None
        self._router_error_index: Optional[Dict[bytes, Dict[str, Any]]] = None
        self._router_abi_path: Optional[str] = None
        self._quoter_abi: Optional[List[Dict[str, Any]]] = None
        self._quoter_abi_path: Optional[str] = None
        self._whbar_evm: Optional[str] = None
        self._whbar_helper_abi: Optional[List[Dict[str, Any]]] = None
        self._whbar_helper_error_index: Optional[Dict[bytes, Dict[str, Any]]] = None
        self._whbar_helper_abi_path: Optional[str] = None
        self._whbar_helper_addr: Optional[str] = None
        # Nonfungible Position Manager (NPM)
        self._npm_abi: Optional[List[Dict[str, Any]]] = None
        self._npm_abi_path: Optional[str] = None
        self._npm_addr: Optional[str] = None
        self._npm_error_index: Optional[Dict[bytes, Dict[str, Any]]] = None
        # LP NFT HTS id (para asociación previa al mint)
        self._lp_nft_id: Optional[str] = None
        # Factory / Pool / TickLens ABIs
        self._factory_abi: Optional[List[Dict[str, Any]]] = None
        self._factory_abi_path: Optional[str] = None
        self._pool_abi: Optional[List[Dict[str, Any]]] = None
        self._pool_abi_path: Optional[str] = None
        self._tick_lens_abi: Optional[List[Dict[str, Any]]] = None
        self._tick_lens_abi_path: Optional[str] = None
        # MasterChef (conversion tinycents -> tinybars y otros parámetros)
        self._master_chef_abi: Optional[List[Dict[str, Any]]] = None
        self._master_chef_abi_path: Optional[str] = None
        self._master_chef_addr: Optional[str] = None

        # Resolver rutas ABI desde YAML si están presentes
        try:
            abi_cfg = self.config.abi_files or {}
            self._router_abi_path = self._resolve_path_from_project_root(abi_cfg.get("swap_router"))
            self._quoter_abi_path = self._resolve_path_from_project_root(abi_cfg.get("quoter_v2"))
            self._whbar_helper_abi_path = self._resolve_path_from_project_root(abi_cfg.get("whbar_helper"))
            self._npm_abi_path = self._resolve_path_from_project_root(abi_cfg.get("nonfungible_position_manager"))
            self._factory_abi_path = self._resolve_path_from_project_root(abi_cfg.get("factory_v2"))
            self._pool_abi_path = self._resolve_path_from_project_root(abi_cfg.get("pool"))
            self._tick_lens_abi_path = self._resolve_path_from_project_root(abi_cfg.get("tick_lens"))
            self._master_chef_abi_path = self._resolve_path_from_project_root(abi_cfg.get("master_chef"))
        except Exception:
            pass

        # Resolver dirección del WhbarHelper desde contratos si estuviera configurado
        try:
            helper_hts = (self.config.contracts or {}).get("whbar_helper")
            if helper_hts:
                helper_evm = self._hts_to_evm(helper_hts)
                if isinstance(helper_evm, str) and helper_evm.startswith("0x"):
                    self._whbar_helper_addr = helper_evm
        except Exception:
            pass

        # Resolver dirección del NPM y LP NFT id si estuvieran configurados
        try:
            npm_hts = (self.config.contracts or {}).get("nonfungible_position_manager")
            if npm_hts:
                npm_evm = self._hts_to_evm(npm_hts)
                if isinstance(npm_evm, str) and npm_evm.startswith("0x"):
                    self._npm_addr = npm_evm
            self._lp_nft_id = (self.config.contracts or {}).get("lp_nft_id")
        except Exception:
            pass

        # Resolver dirección de Factory V2 si estuviera configurada (para mintFee)
        try:
            self._factory_hts: Optional[str] = (self.config.contracts or {}).get("factory_v2")
            self._factory_evm: Optional[str] = None
            if self._factory_hts:
                evm = self._hts_to_evm(self._factory_hts)
                if isinstance(evm, str) and evm.startswith("0x"):
                    self._factory_evm = evm
            # MasterChef address
            mc_hts = (self.config.contracts or {}).get("master_chef")
            if mc_hts:
                evm = self._hts_to_evm(mc_hts)
                if isinstance(evm, str) and evm.startswith("0x"):
                    self._master_chef_addr = evm
        except Exception:
            self._factory_hts = None
            self._factory_evm = None
            self._master_chef_addr = None

    # ---------------- Claves/EVM helpers ----------------
    def _extract_private_key_hex(self, key_json: Dict[str, Any]) -> str:
        # Admite campos: evm_private_key, private_key, operator_private_key, privkey
        candidates = [
            key_json.get("evm_private_key"),
            key_json.get("private_key"),
            key_json.get("operator_private_key"),
            key_json.get("privkey"),
        ]
        pk = next((x for x in candidates if isinstance(x, str) and len(x) > 0), None)
        if not pk:
            raise RuntimeError("No se encontró clave privada en el keyfile (evm_private_key/private_key)")
        pk = pk.strip()
        if pk.startswith("0x"):
            pk = pk[2:]
        # Clave secp256k1 de 32 bytes
        if len(pk) != 64:
            raise RuntimeError("La clave privada no parece ser un hex secp256k1 de 32 bytes")
        # Validación hex
        try:
            bytes.fromhex(pk)
        except Exception:
            raise RuntimeError("Clave privada no es hex válida")
        return pk

    def _derive_evm_address_from_private_key(self, priv_hex: str) -> str:
        try:
            from eth_keys import keys  # type: ignore
            from eth_utils import to_checksum_address  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Falta dependencia para derivar EVM address: {exc}")
        private_key_bytes = bytes.fromhex(priv_hex)
        pk = keys.PrivateKey(private_key_bytes)
        return to_checksum_address(pk.public_key.to_checksum_address())

    # ---------------- ABI helpers ----------------
    def _make_client(self):
        try:
            from hedera import Client as HClient  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Hedera SDK no disponible: {exc}")
        net = (self.config.network or "mainnet").lower()
        candidates = []
        if net == "testnet":
            candidates = ["for_testnet", "forTestnet"]
        elif net == "previewnet":
            candidates = ["for_previewnet", "forPreviewnet"]
        else:
            candidates = ["for_mainnet", "forMainnet"]
        for name in candidates:
            fn = getattr(HClient, name, None)
            if callable(fn):
                return fn()
        raise RuntimeError("No se pudo crear Client para la red Hedera especificada")

    def _load_hedera_private_key(self, priv_str: str):
        """Carga una clave privada ECDSA para Hedera intentando múltiples constructores.
        Acepta hex con o sin 0x.
        """
        try:
            from hedera import PrivateKey as HPrivateKey  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Hedera SDK no disponible: {exc}")
        candidates = []
        # Normaliza hex
        p = priv_str.strip()
        if p.startswith("0x"):
            p_hex = p[2:]
        else:
            p_hex = p
        # Orden de prueba de constructores
        candidates.append(lambda: getattr(HPrivateKey, "fromStringECDSA", None) and HPrivateKey.fromStringECDSA(p))
        candidates.append(lambda: HPrivateKey.fromString(p))
        candidates.append(lambda: getattr(HPrivateKey, "fromBytesECDSA", None) and HPrivateKey.fromBytesECDSA(bytes.fromhex(p_hex)))
        candidates.append(lambda: HPrivateKey.fromBytes(bytes.fromhex(p_hex)))
        last_err: Optional[Exception] = None
        for build in candidates:
            try:
                key = build()
                if key is not None:
                    return key
            except Exception as exc:  # pragma: no cover
                last_err = exc
                continue
        raise RuntimeError(f"No se pudo cargar la clave privada ECDSA: {last_err}")
    def _project_root(self) -> str:
        return get_project_root(__file__)

    def _resolve_path_from_project_root(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        if os.path.isabs(path):
            return path
        return os.path.abspath(os.path.join(self._project_root(), path))

    def _get_router_abi_path(self) -> str:
        if self._router_abi_path and os.path.exists(self._router_abi_path):
            return self._router_abi_path
        # Fallback: LiquidityProvider/SaucerSwap/config/SwapRouter.json
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "config", "SwapRouter.json")

    def _get_quoter_abi_path(self) -> Optional[str]:
        if self._quoter_abi_path and os.path.exists(self._quoter_abi_path):
            return self._quoter_abi_path
        # opcional: QuoterV2.json en config si estuviera presente con ese nombre
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate = os.path.join(base, "config", "QuoterV2.json")
        return candidate if os.path.exists(candidate) else None

    def _get_router_address_evm(self) -> Optional[str]:
        router_hts = self.config.contracts.get("swap_router", "")
        router_evm = self._hts_to_evm(router_hts)
        return router_evm if isinstance(router_evm, str) and router_evm.startswith("0x") else None

    def _get_whbar_evm_from_router(self) -> Optional[str]:
        if self._whbar_evm:
            return self._whbar_evm
        try:
            import eth_utils  # type: ignore
            from eth_abi import decode as abi_decode  # type: ignore
        except Exception:
            return None
        self._ensure_router_abi_loaded()
        # Intentar whbar() y WHBAR()
        for fn in ("whbar", "WHBAR"):
            entry = self._abi_find_function(self._router_abi, fn, []) or {}
            selector = self._abi_selector_from_entry(entry) or eth_utils.keccak(text=f"{fn}()")[:4]
            router = self._get_router_address_evm()
            if not router:
                return None
            try:
                res = self._call_rpc("eth_call", [{"to": router, "data": "0x" + selector.hex()}, "latest"])
                addr = abi_decode(["address"], bytes.fromhex(res[2:]))[0]
                addr_str = addr if isinstance(addr, str) else None
                # Algunos decoders retornan bytes20; forzamos a 0x...
                if not addr_str or not isinstance(addr_str, str) or not addr_str.startswith("0x"):
                    try:
                        addr_str = "0x" + bytes(addr).hex()  # type: ignore
                    except Exception:
                        pass
                if addr_str and addr_str.startswith("0x"):
                    self._whbar_evm = addr_str
                    return self._whbar_evm
            except Exception:
                continue
        return None

    def _ensure_router_abi_loaded(self) -> None:
        if self._router_abi is not None and self._router_error_index is not None:
            return
        path = self._get_router_abi_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._router_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar SwapRouter ABI: %s", exc)
            self._router_abi = []
        # Construir índice de errores por selector
        self._router_error_index = {}
        try:
            import eth_utils  # type: ignore
        except Exception:
            return
        for entry in self._router_abi or []:
            if entry.get("type") == "error":
                name = entry.get("name")
                inputs = entry.get("inputs", [])
                types = ",".join(i.get("type") for i in inputs)
                sig = f"{name}({types})"
                selector = eth_utils.keccak(text=sig)[:4]
                self._router_error_index[bytes(selector)] = {"name": name, "inputs": inputs}

    def _ensure_quoter_abi_loaded(self) -> None:
        if self._quoter_abi is not None:
            return
        path = self._get_quoter_abi_path()
        if not path:
            self._quoter_abi = []
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._quoter_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar Quoter ABI: %s", exc)
            self._quoter_abi = []

    def _get_whbar_helper_abi_path(self) -> Optional[str]:
        if self._whbar_helper_abi_path and os.path.exists(self._whbar_helper_abi_path):
            return self._whbar_helper_abi_path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate = os.path.join(base, "config", "abi", "WhbarHelper.json")
        return candidate if os.path.exists(candidate) else None

    def _ensure_whbar_helper_abi_loaded(self) -> None:
        if self._whbar_helper_abi is not None and self._whbar_helper_error_index is not None:
            return
        path = self._get_whbar_helper_abi_path()
        if not path:
            self._whbar_helper_abi = []
            self._whbar_helper_error_index = {}
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._whbar_helper_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar WhbarHelper ABI: %s", exc)
            self._whbar_helper_abi = []
        # Construir índice de errores personalizados
        self._whbar_helper_error_index = {}
        try:
            import eth_utils  # type: ignore
        except Exception:
            return
        for entry in self._whbar_helper_abi or []:
            if entry.get("type") == "error":
                name = entry.get("name")
                inputs = entry.get("inputs", [])
                types = ",".join(i.get("type") for i in inputs)
                sig = f"{name}({types})"
                selector = eth_utils.keccak(text=sig)[:4]
                self._whbar_helper_error_index[bytes(selector)] = {"name": name, "inputs": inputs}

    # ---------------- NonfungiblePositionManager (NPM) ABI ----------------
    def _get_npm_abi_path(self) -> Optional[str]:
        if self._npm_abi_path and os.path.exists(self._npm_abi_path):
            return self._npm_abi_path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate = os.path.join(base, "config", "abi", "NonfungiblePositionManager.json")
        return candidate if os.path.exists(candidate) else None

    def _ensure_npm_abi_loaded(self) -> None:
        if self._npm_abi is not None and self._npm_error_index is not None:
            return
        path = self._get_npm_abi_path()
        if not path:
            self._npm_abi = []
            self._npm_error_index = {}
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._npm_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar NPM ABI: %s", exc)
            self._npm_abi = []
        # Construir índice de errores del NPM
        self._npm_error_index = {}
        try:
            import eth_utils  # type: ignore
        except Exception:
            return
        for entry in self._npm_abi or []:
            if entry.get("type") == "error":
                name = entry.get("name")
                inputs = entry.get("inputs", [])
                types = ",".join(i.get("type") for i in inputs)
                sig = f"{name}({types})"
                selector = eth_utils.keccak(text=sig)[:4]
                self._npm_error_index[bytes(selector)] = {"name": name, "inputs": inputs}

    def _get_npm_address_evm(self) -> Optional[str]:
        return self._npm_addr

    def _whbar_token_id(self) -> Optional[str]:
        evm = self._get_whbar_evm_from_router()
        return self._evm_to_hts(evm) if evm else None

    def _get_whbar_helper_address(self) -> Optional[str]:
        # Si no está en config, intentamos leer desde el router si expusiera helper (no estándar)
        return self._whbar_helper_addr

    def _whbar_helper_token_address(self) -> Optional[str]:
        """Llama a whbarToken() en el helper para obtener el address del token WHBAR."""
        try:
            import eth_utils  # type: ignore
            from eth_abi import decode as abi_decode  # type: ignore
        except Exception:
            return None
        self._ensure_whbar_helper_abi_loaded()
        helper = self._get_whbar_helper_address()
        if not helper:
            return None
        entry = self._abi_find_function(self._whbar_helper_abi, "whbarToken", []) or {}
        selector = self._abi_selector_from_entry(entry)
        if selector is None:
            selector = eth_utils.keccak(text="whbarToken()")[:4]
        try:
            res = self._call_rpc("eth_call", [{"to": helper, "data": "0x" + selector.hex()}, "latest"])
            addr = abi_decode(["address"], bytes.fromhex(res[2:]))[0]
            return addr if isinstance(addr, str) else None
        except Exception:
            return None

    def _erc20_allowance(self, token_addr: str, owner: str, spender: str) -> Optional[int]:
        try:
            import eth_utils  # type: ignore
            from eth_abi import encode as abi_encode, decode as abi_decode  # type: ignore
        except Exception:
            return None
        sel = eth_utils.keccak(text="allowance(address,address)")[:4]
        calldata = sel + abi_encode(["address", "address"], [owner, spender])
        try:
            res = self._call_rpc("eth_call", [{"to": token_addr, "data": "0x" + calldata.hex()}, "latest"])
            val = abi_decode(["uint256"], bytes.fromhex(res[2:]))[0]
            return int(val)
        except Exception:
            return None

    def _erc20_balance_of(self, token_addr: str, owner: str) -> Optional[int]:
        try:
            import eth_utils  # type: ignore
            from eth_abi import encode as abi_encode, decode as abi_decode  # type: ignore
        except Exception:
            return None
        sel = eth_utils.keccak(text="balanceOf(address)")[:4]
        calldata = sel + abi_encode(["address"], [owner])
        try:
            res = self._call_rpc("eth_call", [{"to": token_addr, "data": "0x" + calldata.hex()}, "latest"])
            bal = abi_decode(["uint256"], bytes.fromhex(res[2:]))[0]
            return int(bal)
        except Exception:
            return None

    def get_balance(self, token_id_or_hbar: str) -> Dict[str, Any]:
        """Retorna el balance de la wallet para un token HTS (0.0.x) o HBAR.
        - HBAR: usa Mirror Node account info.
        - HTS (fungible): llama balanceOf vía ERC20 (JSON-RPC) con dirección EVM del token.
        Devuelve {token: ..., raw: int, decimals?: int}.
        """
        if isinstance(token_id_or_hbar, str) and token_id_or_hbar.upper() == "HBAR":
            # Mirror Node: /accounts/{id}
            import requests
            try:
                url = f"https://mainnet.mirrornode.hedera.com/api/v1/accounts/{self.account_id}"
                r = requests.get(url, timeout=15)
                r.raise_for_status()
                data = r.json()
                # balance en tinybar
                tb = int(((data or {}).get("balance") or {}).get("balance", 0))
                return {"token": "HBAR", "raw": tb, "decimals": 8}
            except Exception as exc:
                return {"token": "HBAR", "error": str(exc)}
        # HTS token
        evm = self._hts_to_evm(token_id_or_hbar)
        if not isinstance(evm, str) or not evm.startswith("0x"):
            return {"token": token_id_or_hbar, "error": "token inválido"}
        bal = self._erc20_balance_of(evm, self.evm_address)
        return {"token": token_id_or_hbar, "raw": int(bal or 0)}

    def get_balances(self, tokens: List[str]) -> Dict[str, Any]:
        """Retorna balances para una lista de tokens (HTS o HBAR)."""
        out: Dict[str, Any] = {}
        for t in tokens:
            out[t] = self.get_balance(t)
        return out

    def wallet_state(self) -> Dict[str, Any]:
        """Autodetecta balances HBAR y HTS de la cuenta usando Mirror Node y enriquece con metadata."""
        import requests
        result: Dict[str, Any] = {"balances": {}}
        base = "https://mainnet.mirrornode.hedera.com/api/v1"
        # Cuenta (HBAR)
        r = requests.get(f"{base}/accounts/{self.account_id}", timeout=15)
        r.raise_for_status()
        acc = r.json() or {}
        # HBAR
        try:
            hbar_tb = int(((acc.get("balance") or {}).get("balance", 0)))
            result.setdefault("native", {})["HBAR"] = hbar_tb
        except Exception:
            pass
        # Tokens: usar endpoint dedicado con paginación, y fallback a campo embebido en /accounts
        dec_cache: Dict[str, Any] = {}
        try:
            next_url = f"{base}/accounts/{self.account_id}/tokens?limit=100"
            while next_url:
                tr = requests.get(next_url, timeout=20)
                tr.raise_for_status()
                tj = tr.json() or {}
                items = (tj.get("tokens") or [])
                for t in items:
                    tid = t.get("token_id")
                    bal = int(t.get("balance", 0))
                    result["balances"].setdefault(tid, {"raw": 0})
                    result["balances"][tid]["raw"] = int(result["balances"][tid]["raw"]) + bal
                    # si el endpoint devuelve decimals/symbol, conservarlos
                    if "decimals" in t:
                        result["balances"][tid]["decimals"] = t.get("decimals")
                    if "symbol" in t:
                        result["balances"][tid]["symbol"] = t.get("symbol")
                    if tid and tid not in dec_cache:
                        dec_cache[tid] = None  # marcar para metadata
                # paginación
                links = tj.get("links") or {}
                next_url = links.get("next")
                if isinstance(next_url, str) and next_url and not next_url.startswith("http"):
                    next_url = f"{base}{next_url}"
        except Exception:
            # Fallback: tokens embebidos en /accounts
            tokens_list = (acc.get("tokens") or [])
            for t in tokens_list:
                tid = t.get("token_id")
                bal = int(t.get("balance", 0))
                result["balances"].setdefault(tid, {"raw": 0})
                result["balances"][tid]["raw"] = int(result["balances"][tid]["raw"]) + bal
                if tid and tid not in dec_cache:
                    dec_cache[tid] = None

        # Completar metadata básica de tokens pendientes
        for tid in list(result["balances"].keys()):
            meta = result["balances"].get(tid) or {}
            if meta.get("decimals") is not None and meta.get("symbol") is not None:
                continue
            try:
                tr = requests.get(f"{base}/tokens/{tid}", timeout=10)
                if tr.ok:
                    tj = tr.json() or {}
                    if meta.get("decimals") is None:
                        meta["decimals"] = tj.get("decimals")
                    if meta.get("symbol") is None:
                        meta["symbol"] = tj.get("symbol")
                    result["balances"][tid] = meta
            except Exception:
                continue
        # Filtrar balances en cero
        try:
            bals = result.get("balances") or {}
            result["balances"] = {tid: info for tid, info in bals.items() if int((info or {}).get("raw", 0)) > 0}
        except Exception:
            pass
        return result

    def _whbar_sweep_unwrap(self, owner: str) -> Optional[Dict[str, Any]]:
        """Si el usuario tiene saldo WHBAR > 0, intenta aprobar helper y ejecutar unwrapWhbar(balance)."""
        try:
            import eth_utils  # type: ignore
            from eth_abi import encode as abi_encode  # type: ignore
        except Exception:
            return {"error": "faltan dependencias eth_utils/eth_abi"}
        helper = self._get_whbar_helper_address()
        if not helper:
            return {"skipped": True, "reason": "whbar_helper no configurado"}
        # Obtener token WHBAR desde helper
        token_addr = self._whbar_helper_token_address()
        if not token_addr:
            return {"skipped": True, "reason": "whbarToken no accesible"}
        # Balance
        bal = self._erc20_balance_of(token_addr, owner)
        if not bal or bal <= 0:
            return {"skipped": True, "reason": "saldo WHBAR = 0"}
        # Approve HTS (solo SDK) si allowance < bal
        allowance = self._erc20_allowance(token_addr, owner, helper) or 0
        if allowance < bal:
            token_id_hts = self._evm_to_hts(token_addr) or ""
            spender_hts = self._evm_to_hts(helper) or ""
            if not (token_id_hts and spender_hts):
                return {"skipped": True, "reason": "no se pudo derivar HTS ids para approve"}
            self.approve_hts_execute(token_id=token_id_hts, spender_contract_id=spender_hts, amount=(1 << 63) - 1)
            # Esperar a que se refleje y re-chequear varias veces
            try:
                import time
                for _ in range(20):
                    time.sleep(1)
                    allowance = self._erc20_allowance(token_addr, owner, helper) or 0
                    if allowance >= bal:
                        break
            except Exception:
                pass
        # Si tras aprobaciones la allowance sigue insuficiente, no ejecutar unwrap para evitar gasto inútil
        if allowance < bal:
            return {
                "skipped": True,
                "reason": "allowance insuficiente tras approve HTS",
                "allowance": {"current": allowance, "needed": int(bal)},
            }
        # Llamar unwrapWhbar(uint256)
        self._ensure_whbar_helper_abi_loaded()
        entry = self._abi_find_function(self._whbar_helper_abi, "unwrapWhbar", ["uint256"]) or {}
        selector = self._abi_selector_from_entry(entry) or eth_utils.keccak(text="unwrapWhbar(uint256)")[:4]
        calldata = selector + abi_encode(["uint256"], [int(bal)])
        txu = {"from": owner, "to": helper, "data": "0x" + calldata.hex()}
        res = self.send_transaction(txu, wait=True)
        return {"executed": True, "tx": res, "amount": bal}

    def _abi_find_function(self, abi_list: Optional[List[Dict[str, Any]]], name: str, input_types: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        if not abi_list:
            return None
        for entry in abi_list:
            if entry.get("type") != "function":
                continue
            if entry.get("name") != name:
                continue
            if input_types is None:
                return entry
            ins = [i.get("type") for i in entry.get("inputs", [])]
            if ins == input_types:
                return entry
        return None

    def _abi_selector_from_entry(self, entry: Dict[str, Any]) -> Optional[bytes]:
        try:
            import eth_utils  # type: ignore
        except Exception:
            return None
        try:
            ins = ",".join(i.get("type") for i in entry.get("inputs", []))
            sig = f"{entry.get('name')}({ins})"
            return eth_utils.keccak(text=sig)[:4]
        except Exception:
            return None

    def _abi_output_types(self, entry: Optional[Dict[str, Any]]) -> Optional[List[str]]:
        if not entry:
            return None
        outs = entry.get("outputs") or []
        if not isinstance(outs, list):
            return None
        types: List[str] = []
        for o in outs:
            t = o.get("type")
            if not isinstance(t, str):
                return None
            types.append(t)
        return types or None

    def _decode_revert_data(self, data_hex: str) -> Optional[Dict[str, Any]]:
        # Maneja Error(string), Panic(uint256) y errores personalizados del ABI
        if not data_hex or not isinstance(data_hex, str) or not data_hex.startswith("0x"):
            return None
        try:
            data = bytes.fromhex(data_hex[2:])
        except Exception:
            return None
        if len(data) < 4:
            # Hedera a veces devuelve códigos cortos (p.ej. 0x3078)
            short = data_hex.lower()
            if short == "0x3078":
                return {"type": "HederaStatus", "code": "0x3078"}
            return None
        selector = data[:4]
        try:
            from eth_abi import decode as abi_decode  # type: ignore
        except Exception:
            return None
        # Error(string)
        if selector == bytes.fromhex("08c379a0"):
            try:
                msg = abi_decode(["string"], data[4:])[0]
                return {"type": "Error", "message": msg}
            except Exception:
                return {"type": "Error", "raw": data_hex}
        # Panic(uint256)
        if selector == bytes.fromhex("4e487b71"):
            try:
                code = abi_decode(["uint256"], data[4:])[0]
                return {"type": "Panic", "code": int(code)}
            except Exception:
                return {"type": "Panic", "raw": data_hex}
        # Custom errors: Router
        self._ensure_router_abi_loaded()
        idx_router = self._router_error_index or {}
        if selector in idx_router:
            err = idx_router[selector]
            arg_types = [inp.get("type") for inp in err["inputs"]]
            try:
                values = abi_decode(arg_types, data[4:]) if arg_types else []
                return {"type": err["name"], "args": [int(v) if hasattr(v, "__int__") else v for v in values]}
            except Exception:
                return {"type": err["name"], "raw": data_hex}
        # Custom errors: WhbarHelper
        self._ensure_whbar_helper_abi_loaded()
        idx_helper = self._whbar_helper_error_index or {}
        if selector in idx_helper:
            err = idx_helper[selector]
            arg_types = [inp.get("type") for inp in err["inputs"]]
            try:
                values = abi_decode(arg_types, data[4:]) if arg_types else []
                return {"type": err["name"], "args": [int(v) if hasattr(v, "__int__") else v for v in values]}
            except Exception:
                return {"type": err["name"], "raw": data_hex}
        # Custom errors: NonfungiblePositionManager
        self._ensure_npm_abi_loaded()
        idx_npm = self._npm_error_index or {}
        if selector in idx_npm:
            err = idx_npm[selector]
            arg_types = [inp.get("type") for inp in err["inputs"]]
            try:
                values = abi_decode(arg_types, data[4:]) if arg_types else []
                return {"type": err["name"], "args": [int(v) if hasattr(v, "__int__") else v for v in values]}
            except Exception:
                return {"type": err["name"], "raw": data_hex}
        return {"type": "Unknown", "raw": data_hex}

    # ---------------- REST posiciones ----------------
    def _saucerswap_positions(self, account_id: str) -> List[Dict[str, Any]]:
        import requests
        api_url = self.config.api_base.rstrip("/") + f"/v2/nfts/{account_id}/positions"
        headers = {"x-api-key": self.api_key, "Accept": "application/json", "User-Agent": "LiquidityProvider/1.0"}
        r = requests.get(api_url, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def position_belongs_to_pool(self, position: Union[int, str], pool_id: Optional[Union[int, str]] = None) -> Dict[str, Any]:
        """Busca una posición por position (NFT) del owner y reporta si pertenece a la pool indicada.
        Devuelve detalles limpios y bandera belongs.
        """
        if position is None:
            return {"ok": False, "error": "missing position"}
        try:
            positions = self._saucerswap_positions(self.account_id)
        except Exception as exc:
            return {"ok": False, "error": f"saucerswap api failed: {exc}"}
        target = None
        for pos in positions:
            try:
                if int(pos.get("tokenSN")) == int(position):
                    target = self._strip_fields(pos)
                    break
            except Exception:
                continue
        if not target:
            return {"ok": False, "position": int(position), "error": "position not found"}
        pid = target.get("poolId") or target.get("pool_id") or ((target.get("pool") or {}).get("id"))
        if pid is None:
            # Resolver poolId vía tokens+fee si no viene en la respuesta
            try:
                t0 = ((target or {}).get("token0") or {}).get("id")
                t1 = ((target or {}).get("token1") or {}).get("id")
                fee_bps = int((target or {}).get("fee")) if (target or {}).get("fee") is not None else None
                if isinstance(t0, str) and isinstance(t1, str) and isinstance(fee_bps, int):
                    pe = self.pool_exists(t0, t1, fee_bps)
                    cand = (pe or {}).get("poolId")
                    if cand is not None:
                        pid = cand
            except Exception:
                pass
        belongs = True if pool_id is None else (str(pid) == str(pool_id))
        # tick actual de la pool desde REST
        try:
            st = self.get_pool_state_decoded(int(pid)) if pid is not None else {}
            tick_current = (st or {}).get("tick_current_index")
        except Exception:
            tick_current = None
        # Normalizar salida al formato agnóstico
        try:
            liq_raw = int((target or {}).get("liquidity")) if isinstance((target or {}).get("liquidity"), str) else int((target or {}).get("liquidity", 0))
        except Exception:
            liq_raw = 0
        # fees acumuladas (tokensOwed0/1) si están presentes
        def _parse_int(x: Any) -> Optional[int]:
            try:
                if x is None:
                    return None
                return int(x)
            except Exception:
                try:
                    return int(str(x))
                except Exception:
                    return None
        rewards = {"amount0": _parse_int((target or {}).get("tokensOwed0")), "amount1": _parse_int((target or {}).get("tokensOwed1"))}
        ticks = {"lower": _parse_int((target or {}).get("tickLower")), "upper": _parse_int((target or {}).get("tickUpper")), "current": _parse_int(tick_current)}
        return {"ok": True, "ticks": ticks, "liquidity": liq_raw, "rewards": rewards}

    # ---------------- Pools helpers (REST/on-chain) ----------------
    def pool_exists(self, tokenA: str, tokenB: str, fee_bps: int) -> Dict[str, Any]:
        """Comprueba existencia de una pool V2 por tokens HTS/HBAR y fee (bps) usando REST.
        - Si token es "HBAR", usa WHBAR token id como equivalente.
        Retorna {exists: bool, poolId?: int}.
        """
        import requests
        # Normalizar a HTS ids
        def norm_token(t: str) -> str:
            if isinstance(t, str) and t.upper() == "HBAR":
                return self._whbar_token_id() or ""
            return t
        a = norm_token(tokenA)
        b = norm_token(tokenB)
        if not (a and b):
            return {"exists": False, "reason": "tokens no válidos"}
        url = self.config.api_base.rstrip("/") + "/v2/pools"
        headers = {"x-api-key": self.api_key, "Accept": "application/json", "User-Agent": "LiquidityProvider/1.0"}
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        pools = r.json()
        if not isinstance(pools, list):
            return {"exists": False, "reason": "respuesta inesperada"}
        target = {a, b}
        for p in pools:
            try:
                pa = (p.get("tokenA") or {}).get("id")
                pb = (p.get("tokenB") or {}).get("id")
                fee = int(p.get("fee"))
                if fee == int(fee_bps) and {pa, pb} == target:
                    return {"exists": True, "poolId": p.get("id"), "contractId": p.get("contractId")}
            except Exception:
                continue
        return {"exists": False}

    def get_pool_ratio(self, pool_id: int) -> Dict[str, Any]:
        """Obtiene sqrtRatioX96, tickCurrent y liquidez desde REST de una pool.
        Retorna {sqrtRatioX96, tickCurrent, liquidity}.
        """
        info = self.get_pool_info(pool_id)
        return {
            "sqrtRatioX96": info.get("sqrtRatioX96"),
            "tickCurrent": info.get("tickCurrent"),
            "liquidity": info.get("liquidity"),
        }

    def get_mint_fee(self) -> Dict[str, Any]:
        # Obtener tinycent on-chain exclusivamente vía MasterChef
        try:
            import eth_utils  # type: ignore
            from eth_abi import decode as abi_decode  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Dependencias faltantes para fee: {exc}")

        if not self._master_chef_addr:
            raise RuntimeError("master_chef debe estar configurado en YAML")

        sel_df = eth_utils.keccak(text="depositFee()")[:4]
        res_df = self._call_rpc("eth_call", [{"to": self._master_chef_addr, "data": "0x" + sel_df.hex()}, "latest"])
        tinycent = int(abi_decode(["uint256"], bytes.fromhex(res_df[2:]))[0])
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("get_mint_fee: masterChef.depositFee tinycent=%s", tinycent)

        # 2) tinycent -> tinybars vía MasterChef.tinycentsToTinybars(uint256)
        if not self._master_chef_addr:
            raise RuntimeError("master_chef no configurado; no se permite fallback")
        sel_tc = eth_utils.keccak(text="tinycentsToTinybars(uint256)")[:4]
        calldata = sel_tc + int(tinycent).to_bytes(32, byteorder="big")
        res2 = self._call_rpc("eth_call", [{"to": self._master_chef_addr, "data": "0x" + calldata.hex()}, "latest"])
        tinybar = int(abi_decode(["uint256"], bytes.fromhex(res2[2:]))[0])
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("get_mint_fee: tinybar=%s (from tinycent=%s)", tinybar, tinycent)

        # 3) tinybar -> wei (1 tinybar = 1e10 wei)
        wei = tinybar * (10 ** 10)
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("get_mint_fee: wei=%s source=master_chef", wei)
        return {"supported": True, "tinycent": int(tinycent), "tinybar": int(tinybar), "wei": int(wei), "source": "master_chef"}

    def _mirror_exchange_rate(self) -> Dict[str, Any]:
        """Obtiene el tipo de cambio cent<->HBAR del Mirror Node.
        Retorna tinybar por cent: (hbar_equivalent * 1e8) / cent_equivalent.
        """
        import requests
        url = "https://mainnet.mirrornode.hedera.com/api/v1/network/exchangerate"
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            data = r.json()
            cur = (data.get("current_rate") or data.get("current_rates") or {}).get("cent_equivalent")
            hbar_eq = (data.get("current_rate") or data.get("current_rates") or {}).get("hbar_equivalent")
            # Ajustar si el JSON viene en formato lista {"current_rate": {..}}
            if cur is None or hbar_eq is None:
                cr = data.get("current_rate") or data.get("current_rates")
                if isinstance(cr, dict):
                    cur = cr.get("cent_equivalent")
                    hbar_eq = cr.get("hbar_equivalent")
            cur = int(cur)
            hbar_eq = int(hbar_eq)
            if cur <= 0 or hbar_eq <= 0:
                return {"ok": False, "reason": "exchange rate inválido"}
            tinybar_per_cent = (hbar_eq * (10 ** 8)) // cur
            return {"ok": True, "tinybar_per_cent": int(tinybar_per_cent)}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}

    # ---------------- Tick math & amounts (cliente, alta precisión) ----------------
    def _round_tick_to_spacing(self, tick: int, tick_spacing: int, mode: str = "floor") -> int:
        if tick_spacing <= 0:
            return tick
        if mode == "ceil":
            return ((tick + tick_spacing - 1) // tick_spacing) * tick_spacing
        # floor por defecto
        return (tick // tick_spacing) * tick_spacing

    def _sqrt_ratio_x96_from_tick(self, tick: int) -> int:
        # Precisión alta vía Decimal: sqrtPriceX96 = floor( (1.0001)^(tick/2) * 2^96 )
        from decimal import Decimal, getcontext
        getcontext().prec = 80
        Q96 = Decimal(2) ** 96
        base = Decimal("1.0001")
        exp = Decimal(tick) / Decimal(2)
        sqrt_price = base ** exp
        val = sqrt_price * Q96
        return int(val)  # floor

    def _tick_from_sqrt_ratio_x96(self, sqrt_ratio_x96: int) -> int:
        # tick ≈ floor( ln( (sqrt_ratio_x96 / 2^96)^2 ) / ln(1.0001) )
        from decimal import Decimal, getcontext
        import math
        getcontext().prec = 80
        Q96 = Decimal(2) ** 96
        sr = Decimal(int(sqrt_ratio_x96)) / Q96
        price = sr * sr
        # usar log natural de float como aproximación (suficiente para guiado)
        t = int(math.floor(math.log(float(price)) / math.log(1.0001)))
        return t

    def _liquidity_for_amounts(self, sqrtP_x96: int, sqrtA_x96: int, sqrtB_x96: int, amount0: int, amount1: int) -> int:
        # Fórmulas estándar Uniswap v3 (escala decimal para claridad)
        from decimal import Decimal, getcontext
        getcontext().prec = 80
        Q96 = Decimal(2) ** 96
        sa = Decimal(min(sqrtA_x96, sqrtB_x96)) / Q96
        sb = Decimal(max(sqrtA_x96, sqrtB_x96)) / Q96
        sp = Decimal(sqrtP_x96) / Q96
        a0 = Decimal(int(amount0))
        a1 = Decimal(int(amount1))
        if sp <= sa:
            # solo token0
            L = a0 * (sa * sb) / (sb - sa)
        elif sp >= sb:
            # solo token1
            L = a1 / (sb - sa)
        else:
            L0 = a0 * (sp * sb) / (sb - sp)
            L1 = a1 / (sp - sa)
            L = min(L0, L1)
        return int(L)

    def _amounts_for_liquidity(self, sqrtP_x96: int, sqrtA_x96: int, sqrtB_x96: int, liquidity: int) -> Tuple[int, int]:
        from decimal import Decimal, getcontext
        getcontext().prec = 80
        Q96 = Decimal(2) ** 96
        sa = Decimal(min(sqrtA_x96, sqrtB_x96)) / Q96
        sb = Decimal(max(sqrtA_x96, sqrtB_x96)) / Q96
        sp = Decimal(sqrtP_x96) / Q96
        L = Decimal(int(liquidity))
        if sp <= sa:
            # todo en token0
            amount0 = L * (sb - sa) / (sa * sb)
            amount1 = Decimal(0)
        elif sp >= sb:
            # todo en token1
            amount0 = Decimal(0)
            amount1 = L * (sb - sa)
        else:
            amount0 = L * (sb - sp) / (sp * sb)
            amount1 = L * (sp - sa)
        return int(amount0), int(amount1)

    # ---------------- Pool: tickSpacing ----------------
    def _pool_tick_spacing(self, pool_contract_evm: str) -> Optional[int]:
        # Lee tickSpacing() del pool si se desea validación fina de ticks
        try:
            import eth_utils  # type: ignore
            from eth_abi import decode as abi_decode  # type: ignore
        except Exception:
            return None
        try:
            sel = eth_utils.keccak(text="tickSpacing()")[:4]
            res = self._call_rpc("eth_call", [{"to": pool_contract_evm, "data": "0x" + sel.hex()}, "latest"])
            val = abi_decode(["int24"], bytes.fromhex(res[2:]))[0]
            return int(val)
        except Exception:
            return None

    # ---------------- Pool: token0/token1 ----------------
    def _pool_token0_token1(self, pool_contract_evm: str) -> Optional[Tuple[str, str]]:
        try:
            import eth_utils  # type: ignore
            from eth_abi import decode as abi_decode  # type: ignore
        except Exception:
            return None
        try:
            sel0 = eth_utils.keccak(text="token0()")[:4]
            sel1 = eth_utils.keccak(text="token1()")[:4]
            r0 = self._call_rpc("eth_call", [{"to": pool_contract_evm, "data": "0x" + sel0.hex()}, "latest"])
            r1 = self._call_rpc("eth_call", [{"to": pool_contract_evm, "data": "0x" + sel1.hex()}, "latest"])
            a0 = abi_decode(["address"], bytes.fromhex(r0[2:]))[0]
            a1 = abi_decode(["address"], bytes.fromhex(r1[2:]))[0]
            if isinstance(a0, str) and isinstance(a1, str):
                return (a0, a1)
            return None
        except Exception:
            return None

    # ---------------- Factory & Pool ABI loaders ----------------
    def _ensure_factory_abi_loaded(self) -> None:
        if self._factory_abi is not None:
            return
        path = self._factory_abi_path
        if not path or not os.path.exists(path):
            self._factory_abi = []
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._factory_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar Factory ABI: %s", exc)
            self._factory_abi = []

    def _ensure_pool_abi_loaded(self) -> None:
        if self._pool_abi is not None:
            return
        path = self._pool_abi_path
        if not path or not os.path.exists(path):
            self._pool_abi = []
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._pool_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar Pool ABI: %s", exc)
            self._pool_abi = []

    def _ensure_tick_lens_abi_loaded(self) -> None:
        if self._tick_lens_abi is not None:
            return
        path = self._tick_lens_abi_path
        if not path or not os.path.exists(path):
            self._tick_lens_abi = []
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._tick_lens_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar TickLens ABI: %s", exc)
            self._tick_lens_abi = []

    def _ensure_master_chef_abi_loaded(self) -> None:
        if self._master_chef_abi is not None:
            return
        path = self._master_chef_abi_path
        if not path or not os.path.exists(path):
            self._master_chef_abi = []
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._master_chef_abi = json.load(f)
        except Exception as exc:
            self.logger.warning("No se pudo cargar MasterChef ABI: %s", exc)
            self._master_chef_abi = []

    # ---------------- Liquidity: Quote/Prepare/Send (por ticks) ----------------
    def liquidity_quote_by_ticks(
        self,
        tokenA: str,
        tokenB: str,
        fee_bps: int,
        tick_lower: int,
        tick_upper: int,
        amount0_desired: int,
        amount1_desired: int,
        slippage_bps: int = 50,
        recipient_evm: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pre-cálculo para nueva posición V2 dado un rango de ticks y amounts deseados.
        - No consulta on-chain cantidades exactas; aplica mínimos via slippage.
        - Verifica existencia de pool (REST) y normaliza tokens (HBAR->WHBAR HTS/EVM).
        Retorna un objeto 'quote' que alimenta liquidity_prepare.
        """
        notes: List[str] = []
        # Normalizar tokens de entrada a HTS ids cuando sea posible para checks/association
        def norm_hts(t: str) -> str:
            if isinstance(t, str) and t.upper() == "HBAR":
                wid = self._whbar_token_id()
                if not wid:
                    raise ValueError("WHBAR no disponible desde router")
                return wid
            return t
        tA_hts = norm_hts(tokenA)
        tB_hts = norm_hts(tokenB)
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("liq_quote: tokens HTS tA=%s tB=%s fee_bps=%s", tA_hts, tB_hts, fee_bps)
        # EVM addresses para NPM
        tA_evm = self._hts_to_evm(tA_hts)
        tB_evm = self._hts_to_evm(tB_hts)
        if not (isinstance(tA_evm, str) and tA_evm.startswith("0x") and isinstance(tB_evm, str) and tB_evm.startswith("0x")):
            raise ValueError("No se pudieron derivar direcciones EVM de tokenA/tokenB")

        # Validación básica de ticks
        if not isinstance(tick_lower, int) or not isinstance(tick_upper, int) or tick_lower >= tick_upper:
            raise ValueError("tick_lower/tick_upper inválidos (tick_lower < tick_upper)")

        # Comprobar existencia de pool
        p = self.pool_exists(tA_hts, tB_hts, int(fee_bps))
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("liq_quote: pool_exists -> %s", p)
        if not p.get("exists"):
            return {"exists": False, "reason": "pool no existe", "details": p}

        pool_id = p.get("poolId")

        # Mínimos por slippage (simple). Con slippage_bps=0 forzamos mínimos a 0 (máxima flexibilidad)
        slip = max(0, int(slippage_bps))
        if slip == 0:
            amt0_min = 0
            amt1_min = 0
        else:
            amt0_min = (int(amount0_desired) * (10000 - slip)) // 10000
            amt1_min = (int(amount1_desired) * (10000 - slip)) // 10000

        out = {
            "exists": True,
            "kind": "liquidity_by_ticks",
            "tokens": {
                "tokenA_hts": tA_hts,
                "tokenB_hts": tB_hts,
                "tokenA_evm": tA_evm,
                "tokenB_evm": tB_evm,
            },
            "fee_bps": int(fee_bps),
            "ticks": {"lower": int(tick_lower), "upper": int(tick_upper)},
            "amounts": {
                "amount0Desired": int(amount0_desired),
                "amount1Desired": int(amount1_desired),
                "amount0Min": int(amt0_min),
                "amount1Min": int(amt1_min),
            },
            "pool": {"poolId": pool_id, "contractId": p.get("contractId")},
            "slippage_bps": int(slippage_bps),
            "recipient": recipient_evm or self.evm_address,
            "notes": notes,
        }
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                "liq_quote: ticks [%s,%s] amounts(desired)=(%s,%s) mins=(%s,%s) poolId=%s",
                out["ticks"]["lower"], out["ticks"]["upper"],
                out["amounts"]["amount0Desired"], out["amounts"]["amount1Desired"],
                out["amounts"]["amount0Min"], out["amounts"]["amount1Min"], pool_id
            )
        return out

    def liquidity_prepare(self, quote: Dict[str, Any], deadline_s: int = 300) -> Dict[str, Any]:
        """Prepara calldata para NonfungiblePositionManager.mint(...) a partir de 'quote'.
        - Auto-asocia tokens A/B y LP NFT si faltan.
        - Prepara approve(MAX) al NPM si allowance insuficiente.
        - No envía la transacción; devuelve {to,data,value,gasEstimate,approve?,association?}.
        """
        from eth_abi import encode as abi_encode  # type: ignore
        import eth_utils  # type: ignore
        import time

        if not isinstance(quote, dict) or not quote.get("exists"):
            raise ValueError("quote inválido o pool no existe")
        self._ensure_npm_abi_loaded()
        npm = self._get_npm_address_evm()
        if not npm:
            raise ValueError("nonfungible_position_manager no configurado correctamente")

        tokens = quote.get("tokens", {})
        tA_hts = tokens.get("tokenA_hts")
        tB_hts = tokens.get("tokenB_hts")
        tA_evm = tokens.get("tokenA_evm")
        tB_evm = tokens.get("tokenB_evm")
        fee_bps = int(quote.get("fee_bps"))
        ticks = quote.get("ticks", {})
        tick_lower = int(ticks.get("lower"))
        tick_upper = int(ticks.get("upper"))
        amts = quote.get("amounts", {})
        amt0_des = int(amts.get("amount0Desired", 0))
        amt1_des = int(amts.get("amount1Desired", 0))
        # Forzar mins=0 para evitar Price slippage check en presupuestos pequeños
        amt0_min = 0
        amt1_min = 0
        recipient = quote.get("recipient") or self.evm_address

        notes: List[str] = []
        association: Dict[str, Any] = {"executed": False, "steps": []}
        approve_steps: List[Dict[str, Any]] = []
        can_send: bool = True

        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                "liq_prep: npm=%s fee_bps=%s ticks=[%s,%s] amounts(desired)=(%s,%s) mins=(%s,%s) recipient=%s",
                npm, fee_bps, tick_lower, tick_upper, amt0_des, amt1_des, amt0_min, amt1_min, recipient
            )

        # Asociar HTS tokens A/B y LP NFT (forzar vía SDK para evitar lag del Mirror)
        try:
            to_assoc_set = set()
            for t in (tA_hts, tB_hts):
                if isinstance(t, str) and t.count(".") == 2:
                    to_assoc_set.add(t)
            if self._lp_nft_id and isinstance(self._lp_nft_id, str):
                to_assoc_set.add(self._lp_nft_id)
            to_assoc = [x for x in to_assoc_set]
            if to_assoc:
                res = self.associate_execute(to_assoc)
                association = res
                # pequeña espera para propagación
                try:
                    import time as _t
                    _t.sleep(2)
                except Exception:
                    pass
        except Exception as exc:
            notes.append(f"association error: {exc}")

        # Asociación del contrato NPM a los tokens HTS (mejor esfuerzo)
        try:
            npm_hts_chk = self._evm_to_hts(npm)
            need_assoc: List[str] = []
            for t_hts in (tA_hts, tB_hts):
                if isinstance(t_hts, str) and t_hts.count(".") == 2:
                    chk_c = self.check_contract_associated(t_hts, npm_hts_chk)
                    if not chk_c.get("associated", False):
                        need_assoc.append(t_hts)
            if need_assoc:
                res_ca = self.associate_contract_execute(need_assoc, npm_hts_chk)
                notes.append(f"associate_contract: {res_ca}")
        except Exception as exc:
            notes.append(f"contract association check/exec warn: {exc}")

        deadline_ts = int(time.time()) + int(deadline_s)

        # Construir calldata mint((...))
        # Reordenar tokens/amounts a token0/token1 del pool
        pool_id_hts = (quote.get("pool") or {}).get("contractId")
        pool_evm_addr = self._hts_to_evm(pool_id_hts) if pool_id_hts else None
        # Canonizar pool si el contractId HTS no resuelve a un EVM válido
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("liq_prep: pool_id_hts=%s evm=%s", pool_id_hts, pool_evm_addr)
        if not (isinstance(pool_evm_addr, str) and pool_evm_addr.startswith("0x")):
            try:
                if not (isinstance(tA_evm, str) and tA_evm.startswith("0x") and isinstance(tB_evm, str) and tB_evm.startswith("0x")):
                    raise ValueError("tokens EVM inválidos para resolver pool")
                if not self._factory_evm:
                    raise ValueError("factory_v2 no configurada en YAML")
                import eth_utils  # type: ignore
                sel = eth_utils.keccak(text="getPool(address,address,uint24)")[:4]
                def enc_addr(a: str) -> str: return a[2:].zfill(64)
                def enc_u24(x: int) -> str: return hex(int(x))[2:].zfill(64)
                data_ab = "0x" + sel.hex() + enc_addr(tA_evm) + enc_addr(tB_evm) + enc_u24(fee_bps)
                data_ba = "0x" + sel.hex() + enc_addr(tB_evm) + enc_addr(tA_evm) + enc_u24(fee_bps)
                r_ab = self._call_rpc("eth_call", [{"to": self._factory_evm, "data": data_ab}, "latest"]) or "0x0"
                r_ba = self._call_rpc("eth_call", [{"to": self._factory_evm, "data": data_ba}, "latest"]) or "0x0"
                evm_sel = r_ab if int(r_ab, 16) != 0 else r_ba
                if int(evm_sel, 16) != 0:
                    pool_evm_addr = "0x" + evm_sel[2:][-40:]
                    resolved_hts = self._resolve_contract_hts_via_mirror(pool_evm_addr)
                    if resolved_hts:
                        pool_id_hts = resolved_hts
                        if isinstance(quote.get("pool"), dict):
                            quote["pool"]["contractId"] = resolved_hts
                        else:
                            quote["pool"] = {"contractId": resolved_hts}
                    if self.logger.isEnabledFor(logging.INFO):
                        self.logger.info("liq_prep: pool canonicalizado via Factory.getPool evm=%s hts=%s", pool_evm_addr, resolved_hts)
                    notes.append("pool canonicalizado via Factory.getPool")
            except Exception as _exc:
                if self.logger.isEnabledFor(logging.WARNING):
                    self.logger.warning("liq_prep: pool canonicalización fallida: %s", _exc)
                notes.append(f"pool canonicalización fallida: {_exc}")
        # Nota: verificar asociación del Pool (contrato) con tokens HTS (esperado por el protocolo); no bloqueante
        try:
            pool_hts_chk = pool_id_hts
            if isinstance(pool_hts_chk, str):
                for t_hts in (tA_hts, tB_hts):
                    if isinstance(t_hts, str) and t_hts.count(".") == 2:
                        chk_p = self.check_contract_associated(t_hts, pool_hts_chk)
                        if not chk_p.get("associated", False):
                            notes.append(f"Pool no asociado a {t_hts} segun Mirror (no bloqueante)")
        except Exception as exc:
            notes.append(f"pool association check warn: {exc}")
        useA_evm, useB_evm = tA_evm, tB_evm
        a0_des, a1_des, a0_min, a1_min = amt0_des, amt1_des, amt0_min, amt1_min
        if pool_evm_addr:
            tk = self._pool_token0_token1(pool_evm_addr)
            if tk and isinstance(tk[0], str) and isinstance(tk[1], str):
                token0, token1 = tk
                # Mapear A/B a 0/1
                if (tA_evm.lower() != token0.lower()) or (tB_evm.lower() != token1.lower()):
                    # Permutar
                    useA_evm, useB_evm = token0, token1
                    # Si A no es token0, intercambiar amounts
                    a0_des, a1_des = (amt1_des, amt0_des)
                    a0_min, a1_min = (amt1_min, amt0_min)
            # No forzar snapping de ticks; seguimos los que vienen del quote para igualar el flujo de la UI
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("liq_prep: token0=%s token1=%s amounts0/1=%s/%s mins0/1=%s/%s",
                              useA_evm, useB_evm, a0_des, a1_des, a0_min, a1_min)

        # Approvals MAX al NPM (HTS allowance) basados en token0/token1 efectivos
        try:
            npm_hts = self._evm_to_hts(npm)
            pool_hts_eff = pool_id_hts
            # Determinar los HTS ids correspondientes a token0/token1 efectivas
            token0_hts = tA_hts if useA_evm.lower() == tA_evm.lower() else tB_hts
            token1_hts = tB_hts if useB_evm.lower() == tB_evm.lower() else tA_hts
            # token0
            if int(a0_des) > 0 and isinstance(token0_hts, str) and token0_hts.upper() != "HBAR":
                # allowance_check soporta tanto HTS (convierte a EVM) como direcciones EVM
                alw0 = self.allowance_check(token0_hts, spender=npm_hts)
                if int(alw0.get("allowance", 0)) < int(a0_des):
                    if token0_hts.count(".") == 2:
                        res0 = self.approve_hts_execute(token_id=token0_hts, spender_contract_id=npm_hts)
                        approve_steps.append({"hts_allow_token0": res0})
                        # Poll hasta ver allowance suficiente
                        try:
                            import time as _t
                            for _ in range(20):
                                _t.sleep(1)
                                chk0 = self.allowance_check(token0_hts, spender=npm_hts)
                                if int(chk0.get("allowance", 0)) >= int(a0_des):
                                    break
                        except Exception:
                            pass
                    else:
                        notes.append("token0 no HTS: se omite approve HTS explícito (usar allowance ERC20 si aplica)")
            # token1
            if int(a1_des) > 0 and isinstance(token1_hts, str) and token1_hts.upper() != "HBAR":
                alw1 = self.allowance_check(token1_hts, spender=npm_hts)
                if int(alw1.get("allowance", 0)) < int(a1_des):
                    if token1_hts.count(".") == 2:
                        res1 = self.approve_hts_execute(token_id=token1_hts, spender_contract_id=npm_hts)
                        approve_steps.append({"hts_allow_token1": res1})
                        try:
                            import time as _t
                            for _ in range(20):
                                _t.sleep(1)
                                chk1 = self.allowance_check(token1_hts, spender=npm_hts)
                                if int(chk1.get("allowance", 0)) >= int(a1_des):
                                    break
                        except Exception:
                            pass
                    else:
                        notes.append("token1 no HTS: se omite approve HTS explícito (usar allowance ERC20 si aplica)")
            # En Hedera algunas rutas usan allowance directo al Pool; añadimos como refuerzo no bloqueante
            if isinstance(pool_hts_eff, str):
                try:
                    if int(a0_des) > 0 and isinstance(token0_hts, str) and token0_hts.upper() != "HBAR":
                        alw0p = self.allowance_check(token0_hts, spender=pool_hts_eff)
                        if int(alw0p.get("allowance", 0)) < int(a0_des):
                            if token0_hts.count(".") == 2:
                                res0p = self.approve_hts_execute(token_id=token0_hts, spender_contract_id=pool_hts_eff)
                                approve_steps.append({"hts_allow_token0_pool": res0p})
                            else:
                                notes.append("token0 no HTS: se omite approve HTS al Pool")
                    if int(a1_des) > 0 and isinstance(token1_hts, str) and token1_hts.upper() != "HBAR":
                        alw1p = self.allowance_check(token1_hts, spender=pool_hts_eff)
                        if int(alw1p.get("allowance", 0)) < int(a1_des):
                            if token1_hts.count(".") == 2:
                                res1p = self.approve_hts_execute(token_id=token1_hts, spender_contract_id=pool_hts_eff)
                                approve_steps.append({"hts_allow_token1_pool": res1p})
                            else:
                                notes.append("token1 no HTS: se omite approve HTS al Pool")
                except Exception as _ex2:
                    notes.append(f"pool allowance check warn: {_ex2}")
        except Exception as exc:
            notes.append(f"hts allow error (post-reorder): {exc}")

        # Construir multicall([mint(params), refundETH()]) según docs oficiales
        entry_mint = self._abi_find_function(self._npm_abi, "mint", [
            "(address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256)"
        ]) or {}
        # Selector canónico de UniswapV3 NPM.mint = 0x88316456
        sel_mint = bytes.fromhex("88316456")
        params_tuple = (
            useA_evm, useB_evm, int(fee_bps), int(tick_lower), int(tick_upper),
            int(a0_des), int(a1_des), 0, 0,
            recipient, int(deadline_ts)
        )
        mint_data = sel_mint + abi_encode([
            "(address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256)"
        ], [params_tuple])

        # refundETH()
        sel_refund = eth_utils.keccak(text="refundETH()")[:4]

        # Opcional: sweepToken(address token, uint256 amountMinimum, address recipient) para limpiar restos
        try:
            sel_sweep = eth_utils.keccak(text="sweepToken(address,uint256,address)")[:4]
            sweep0 = sel_sweep + abi_encode(["address", "uint256", "address"], [useA_evm, 0, recipient])
            sweep1 = sel_sweep + abi_encode(["address", "uint256", "address"], [useB_evm, 0, recipient])
        except Exception:
            sel_sweep = None
            sweep0 = None
            sweep1 = None

        # multicall(bytes[])
        entry_mc = self._abi_find_function(self._npm_abi, "multicall", ["bytes[]"]) or {}
        sel_mc = self._abi_selector_from_entry(entry_mc) or eth_utils.keccak(text="multicall(bytes[])")[:4]
        inner_calls = [mint_data]
        # Añadir refund y sweep como en la UI
        inner_calls.append(sel_refund)
        if sweep0 is not None:
            inner_calls.append(sweep0)
        if sweep1 is not None:
            inner_calls.append(sweep1)
        inner_calls.append(sel_refund)
        multicall_data = sel_mc + abi_encode(["bytes[]"], [inner_calls])
        if self.logger.isEnabledFor(logging.DEBUG):
            try:
                self.logger.debug(
                    "liq_prep encoders: sel_mint=%s sel_mc=%s parts_len=[%s,%s,%s,%s] total=%s",
                    sel_mint.hex(), sel_mc.hex(),
                    len(mint_data), len(sel_refund), len(sweep0 or b""), len(sweep1 or b""), len(multicall_data)
                )
            except Exception:
                pass

        tx = {"from": self.evm_address, "to": npm, "data": "0x" + multicall_data.hex()}
        notes.append("mint via multicall([mint, refundETH])")
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("liq_prep: calldata.len=%s", len(tx["data"]))

        # Chequeo de saldos antes de intentar estimar/enviar
        deficit0_raw = 0
        deficit1_raw = 0
        try:
            bal0 = self._erc20_balance_of(useA_evm, self.evm_address)
            bal1 = self._erc20_balance_of(useB_evm, self.evm_address)
            if int(a0_des) > 0 and int(bal0 or 0) < int(a0_des):
                deficit0_raw = int(a0_des) - int(bal0 or 0)
                notes.append(f"saldo insuficiente token0: have={int(bal0 or 0)} need={int(a0_des)}")
            if int(a1_des) > 0 and int(bal1 or 0) < int(a1_des):
                deficit1_raw = int(a1_des) - int(bal1 or 0)
                notes.append(f"saldo insuficiente token1: have={int(bal1 or 0)} need={int(a1_des)}")
        except Exception as exc:
            notes.append(f"balance check error: {exc}")

        # msg.value: cubrir únicamente mintFee (alineado a UI). No enviar déficit WHBAR
        value_hex = None
        try:
            whbar_hts = getattr(self, "_whbar_token_id", lambda: None)()
            if not whbar_hts:
                # Fallback robusto: resolver WHBAR vía helper.whbarToken() -> EVM -> HTS
                try:
                    whbar_evm = self._whbar_helper_token_address()
                    if whbar_evm:
                        whbar_hts = self._evm_to_hts(whbar_evm)
                except Exception:
                    pass
        except Exception:
            whbar_hts = None
        try:
            fee_wei_val = 0
            try:
                mf = self.get_mint_fee()
                if mf.get("supported") and isinstance(mf.get("wei"), int):
                    fee_wei_val = int(mf["wei"])  # tinybars->wei ya convertido en get_mint_fee
            except Exception:
                fee_wei_val = 0
            # Solo mintFee; no añadir déficit WHBAR al value
            total_wei = fee_wei_val
            if total_wei > 0:
                value_hex = hex(total_wei)
                tx["value"] = value_hex
                notes.append(f"msg.value = mintFee({fee_wei_val})")
        except Exception as _vx:
            notes.append(f"value calc warn: {_vx}")

        # Auto-wrap HBAR->WHBAR previo al mint si hay déficit WHBAR y saldo HBAR suficiente
        try:
            auto_wrap_added = False
            helper_addr = self._get_whbar_helper_address()
            # Resolver WHBAR EVM para detección robusta
            whbar_evm_detect = self._get_whbar_evm_from_router() or self._whbar_helper_token_address()
            if helper_addr and helper_addr.startswith("0x"):
                # Detectar déficit WHBAR por HTS o por EVM address
                deficit_wh = 0
                match_side = None
                if isinstance(whbar_hts, str) and whbar_hts:
                    if token0_hts == whbar_hts and deficit0_raw > 0:
                        deficit_wh = int(deficit0_raw); match_side = "A"
                    elif token1_hts == whbar_hts and deficit1_raw > 0:
                        deficit_wh = int(deficit1_raw); match_side = "B"
                if deficit_wh == 0 and isinstance(whbar_evm_detect, str) and whbar_evm_detect.startswith("0x"):
                    if useA_evm.lower() == whbar_evm_detect.lower() and deficit0_raw > 0:
                        deficit_wh = int(deficit0_raw); match_side = "A"
                    elif useB_evm.lower() == whbar_evm_detect.lower() and deficit1_raw > 0:
                        deficit_wh = int(deficit1_raw); match_side = "B"
                if deficit_wh > 0:
                    # Consultar saldo HBAR (tinybars)
                    try:
                        ws = self.wallet_state() or {}
                        hbar_tb = int(((ws.get("native") or {}).get("HBAR", 0)))
                    except Exception:
                        hbar_tb = 0
                    if hbar_tb >= deficit_wh:
                        # Construir tx de wrap: WhbarHelper.deposit() payable con value=deficit_wh * 1e10 wei
                        import eth_utils  # type: ignore
                        sel_deposit = eth_utils.keccak(text="deposit()")[:4]
                        wrap_value_wei = int(deficit_wh) * (10 ** 10)
                        approve_steps.append({
                            "from": self.evm_address,
                            "to": helper_addr,
                            "data": "0x" + sel_deposit.hex(),
                            "value": hex(wrap_value_wei),
                            "kind": "wrap_whbar",
                        })
                        auto_wrap_added = True
                        notes.append(f"auto-wrap WHBAR: side={match_side} deposit tinybars={deficit_wh}")
                        # Si añadimos wrap, permitimos el envío del mint
                        can_send = True
                    else:
                        notes.append(f"auto-wrap skipped: hbar_tb={hbar_tb} < deficit_wh={deficit_wh}")
        except Exception as _awx:
            notes.append(f"auto-wrap warn: {_awx}")

        # Guard de desviación: abortar si el tick actual se alejó demasiado del plan
        try:
            info_now = self.get_pool_state_decoded((quote.get("pool") or {}).get("poolId")) or {}
            tick_now = int(info_now.get("tick_current_index") or 0)
            drift_bps = int(os.environ.get("MINT_TICK_DRIFT_BPS", "200"))
            width = max(1, int(abs(tick_upper - tick_lower)))
            # Aproximación: permitir deriva del centro proporcional
            center = int((tick_upper + tick_lower) // 2)
            drift = abs(tick_now - center)
            if drift * 10000 > width * drift_bps:
                can_send = False
                notes.append(f"guard: tick drift too high now={tick_now} center={center} width={width} bps={drift_bps}")
        except Exception:
            pass

        # Determinar canSend: bloquear si hay déficit de cualquier token (a menos que auto-wrap esté preparado)
        try:
            can_send = True
            if (deficit0_raw > 0 or deficit1_raw > 0) and not locals().get("auto_wrap_added", False):
                can_send = False
        except Exception:
            # Mantener valor anterior en caso de error
            pass

        # Gas fijo recomendado por documentación (900000)
        gas_estimate: Optional[int] = 1375000
        notes.append("mint gasEstimate~1.375M (alineado UI)")
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("liq_prep: gas=%s value=%s canSend=%s notes=%s", gas_estimate, value_hex, can_send, "; ".join(notes))

        return {
            "to": npm,
            "data": "0x" + multicall_data.hex(),
            "value": value_hex,
            "gasEstimate": gas_estimate,
            "from": self.evm_address,
            "association": association,
            "approves": approve_steps if approve_steps else None,
            "notes": notes,
            "canSend": can_send,
            "quote": quote,
            "mintData": "0x" + mint_data.hex(),
            "multicallData": "0x" + multicall_data.hex(),
        }

    def liquidity_send(self, prep: Dict[str, Any], wait: bool = True) -> Dict[str, Any]:
        """Envía aprobaciones opcionales y el mint vía JSON-RPC (eth_sendRawTransaction).
        Requiere que 'prep' provenga de liquidity_prepare. Devuelve steps con receipt y tokenId si es posible.
        """
        results: Dict[str, Any] = {"steps": []}
        # Validación mínima
        to_evm = prep.get("to")
        data_hex = prep.get("data")
        if not (isinstance(to_evm, str) and to_evm.startswith("0x") and isinstance(data_hex, str) and data_hex.startswith("0x")):
            return {"error": "prep inválido: faltan 'to' (0x..) o 'data' (0x..)"}

        # 1) Ejecutar approves previos si existen
        approves = prep.get("approves") or []
        for ap in approves:
            if not ap:
                continue
            txa: Dict[str, Any] = {
                "from": ap.get("from") or self.evm_address,
                "to": ap.get("to"),
                "data": ap.get("data"),
            }
            if ap.get("value"):
                txa["value"] = ap["value"]
            res_a = self.send_transaction(txa, wait=wait)
            results["steps"].append({"approve": res_a})

        # Si hubo intento de wrap y falló, no continuar con el mint
        try:
            helper_addr = self._get_whbar_helper_address()
            wrap_failed = False
            for step in results["steps"]:
                apr = step.get("approve") or {}
                to_addr = ((apr.get("tx") or {}).get("to") or "").lower()
                if helper_addr and to_addr == helper_addr.lower():
                    rec = apr.get("receipt") or {}
                    status_hex = str(rec.get("status") or "0x1")
                    if status_hex != "0x1":
                        wrap_failed = True
                        break
            if wrap_failed:
                results["steps"].append({"skipped_mint": {"error": "wrap_failed"}})
                return results
        except Exception:
            pass

        # Respetar canSend: si es False, no intentar el mint
        try:
            if not bool(prep.get("canSend", True)):
                reason = {
                    "error": "canSend=false",
                    "notes": prep.get("notes"),
                }
                results["steps"].append({"skipped_mint": reason})
                return results
        except Exception:
            pass

        # 2) Enviar mint (multicall) por JSON-RPC
        gas_limit = int(prep.get("gasEstimate") or 1375000)
        txm: Dict[str, Any] = {
            "from": prep.get("from") or self.evm_address,
            "to": to_evm,
            "data": data_hex,
            "gas": gas_limit,
        }
        if prep.get("value"):
            txm["value"] = prep["value"]

        res_m = self.send_transaction(txm, wait=wait)
        try:
            rec = (res_m or {}).get("receipt")
            if rec and isinstance(rec, dict):
                self._log_remove_receipt(rec)
        except Exception:
            pass

        # 4) Intentar extraer tokenId del log Transfer (ERC721). En Hedera la
        #    colección de LP NFTs puede ser un contrato distinto al NPM, así que
        #    buscamos en ambos: NPM y contrato LP NFT (si está configurado).
        token_id = None
        try:
            rec = res_m.get("receipt") or {}
            logs = rec.get("logs") or []
            npm_addr = (self._get_npm_address_evm() or "").lower()
            lp_evm = None
            try:
                if getattr(self, "_lp_nft_id", None):
                    lp_evm = (self._hts_to_evm(self._lp_nft_id) or "").lower()
            except Exception:
                lp_evm = None
            erc721_transfer_sig = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            for lg in logs:
                try:
                    addr = str(lg.get("address", "")).lower()
                    if addr not in filter(None, [npm_addr, lp_evm]):
                        continue
                    topics = lg.get("topics") or []
                    if len(topics) == 4 and str(topics[0]).lower() == erc721_transfer_sig:
                        tok_hex = str(topics[3])
                        if tok_hex.startswith("0x"):
                            token_id = int(tok_hex, 16)
                            break
                except Exception:
                    continue
        except Exception:
            pass

        results["steps"].append({"mint": res_m, "tokenId": token_id})
        return results

    # ---------------- Liquidity REMOVE (decrease + collect + burn) ----------------
    def liquidity_decrease_prepare(
        self,
        serial: int,
        liquidity: int,
        amount0_min: int = 0,
        amount1_min: int = 0,
        deadline_s: int = 900,
        recipient: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Prepara multicall para eliminar liquidez de una posición:
        [decreaseLiquidity, collect, burn, (sweepToken0), (sweepToken1), refundETH].
        - No envía la transacción; devuelve {to,data,value,gasEstimate,notes}.
        - token0_evm/token1_evm opcionales para sweepToken; si no se pasan, se omiten los sweeps.
        """
        from eth_abi import encode as abi_encode  # type: ignore
        import eth_utils  # type: ignore
        import time

        self._ensure_npm_abi_loaded()
        npm = self._get_npm_address_evm()
        if not npm:
            raise ValueError("nonfungible_position_manager no configurado correctamente")

        owner = recipient or self.evm_address
        now = int(time.time())
        # Alinear con UI: deadline en milisegundos
        deadline_ts = (now + int(deadline_s)) * 1000
        notes: List[str] = []

        # decreaseLiquidity((uint256,uint128,uint256,uint256,uint256)) -> 0x0c49ccbe
        sel_dec = eth_utils.keccak(text="decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))")[:4]
        dec_tuple = (int(serial), int(liquidity), int(amount0_min), int(amount1_min), int(deadline_ts))
        dec_data = sel_dec + abi_encode(["(uint256,uint128,uint256,uint256,uint256)"], [dec_tuple])

        # collect plano como en la UI: selector fijo 0xfc6f7865
        sel_collect = bytes.fromhex("fc6f7865")
        max_u128 = (1 << 128) - 1
        col0_data = sel_collect + abi_encode(["uint256", "address", "uint128", "uint128"], [int(serial), owner, int(max_u128), 0])
        col1_data = sel_collect + abi_encode(["uint256", "address", "uint128", "uint128"], [int(serial), owner, 0, int(max_u128)])

        # burn(uint256) -> 0x42966c68
        sel_burn = eth_utils.keccak(text="burn(uint256)")[:4]
        burn_data = sel_burn + abi_encode(["uint256"], [int(serial)])

        # sin unwrapWHBAR: se entregan WHBAR directamente al owner

        # sweepToken del Router no existe en NPM; lo omitimos explícitamente

        # Antes de multicall: aprobar HTS NFT (LP) al NPM para burn transfer
        try:
            lp_nft_id = getattr(self, "_lp_nft_id", None)
            npm_hts = self._resolve_contract_hts_via_mirror(npm) or None
            if lp_nft_id and npm_hts:
                self.approve_hts_nft_execute(token_id=lp_nft_id, serial=int(serial), spender_contract_id=npm_hts)
                notes.append(f"hts approve nft(serial) {lp_nft_id} -> {npm_hts} serial={serial}")
        except Exception as aexc:
            notes.append(f"hts approve warn: {aexc}")

        # multicall(bytes[])
        entry_mc = self._abi_find_function(self._npm_abi, "multicall", ["bytes[]"]) or {}
        sel_mc = self._abi_selector_from_entry(entry_mc) or eth_utils.keccak(text="multicall(bytes[])")[:4]
        # Orden: decrease -> collect0 -> collect1 -> burn
        inner: List[bytes] = [dec_data, col0_data, col1_data, burn_data]
        multicall_data = sel_mc + abi_encode(["bytes[]"], [inner])
        if self.logger.isEnabledFor(logging.DEBUG):
            try:
                self.logger.debug(
                    "remove encoders: sel_dec=%s sel_collect=%s sel_burn=%s sel_mc=%s parts_len=[%s,%s,%s,%s] total=%s",
                    sel_dec.hex(), sel_collect.hex(), sel_burn.hex(), sel_mc.hex(),
                    len(dec_data), len(col0_data), len(col1_data), len(burn_data), len(multicall_data)
                )
            except Exception:
                pass

        tx = {"from": self.evm_address, "to": npm, "data": "0x" + multicall_data.hex()}
        gas_estimate: Optional[int] = 1_750_000
        notes.append("remove gasEstimate~1.75M (alineado UI)")
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                "liq_decrease_prep: tokenId=%s liq=%s mins=(%s,%s) deadline=%s gas=%s",
                serial, liquidity, amount0_min, amount1_min, deadline_ts, gas_estimate,
            )

        return {
            "to": npm,
            "data": "0x" + multicall_data.hex(),
            "from": self.evm_address,
            "gasEstimate": gas_estimate,
            "value": None,
            "notes": notes,
        }

    def liquidity_decrease_send(self, prep: Dict[str, Any], wait: bool = True) -> Dict[str, Any]:
        """Envía la transacción de remove (multicall) por JSON-RPC. Devuelve receipt y cantidades si están en logs.
        Tras el envío, ejecuta siempre un unwrap de WHBAR residual mediante WhbarHelper (en tx separada).
        """
        results: Dict[str, Any] = {"steps": []}
        if not prep or not isinstance(prep.get("to"), str) or not isinstance(prep.get("data"), str):
            return {"error": "prep inválido"}
        tx: Dict[str, Any] = {
            "from": prep.get("from") or self.evm_address,
            "to": prep["to"],
            "data": prep["data"],
            "gas": int(prep.get("gasEstimate") or 1_750_000),
        }
        if prep.get("value"):
            tx["value"] = prep["value"]
        res = self.send_transaction(tx, wait=wait)
        results["steps"].append({"remove": res})
        try:
            rec = (res or {}).get("receipt")
            if rec and isinstance(rec, dict):
                self._log_remove_receipt(rec)
        except Exception:
            pass
        # Auto-sweep obligatorio de WHBAR -> HBAR mediante helper dedicado
        try:
            owner = tx.get("from") or self.evm_address
            sweep = self._whbar_sweep_unwrap(owner)
            if sweep and (sweep.get("executed") or sweep.get("skipped") or sweep.get("error")):
                results["steps"].append({"whbar_sweep": sweep})
        except Exception as exc:
            results["steps"].append({"whbar_sweep": {"error": str(exc)}})
        return results

    def _log_remove_receipt(self, receipt: Dict[str, Any]) -> None:
        """Emite logs útiles del receipt de remove, incluyendo tópicos y tamaños de data."""
        logs_list = receipt.get("logs") or []
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("remove receipt: status=%s gasUsed=%s logs=%s", receipt.get("status"), receipt.get("gasUsed"), len(logs_list))
        for idx, lg in enumerate(logs_list):
            try:
                addr = lg.get("address")
                topics = lg.get("topics") or []
                t0 = topics[0] if topics else None
                data_hex = lg.get("data") or "0x"
                dlen = max(0, (len(data_hex) - 2) // 2)
                if self.logger.isEnabledFor(logging.INFO):
                    self.logger.info("log[%s]: addr=%s topic0=%s data_len=%s", idx, addr, t0, dlen)
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug("log[%s] data=%s", idx, data_hex)
                # Intento simple: si data es múltiplo de 32 bytes hasta 3 palabras, decodificar uints
                if dlen in (32, 64, 96):
                    try:
                        from eth_abi import decode as abi_decode  # type: ignore
                        raw = bytes.fromhex(data_hex[2:])
                        words = dlen // 32
                        types = ["uint256"] * words
                        vals = abi_decode(types, raw)
                        self.logger.info("log[%s] decoded_uints=%s", idx, tuple(int(v) for v in vals))
                    except Exception:
                        pass
            except Exception:
                continue

    def get_pool_info(self, pool_id: Union[int, str]) -> Dict[str, Any]:
        """Obtiene la información pública de una pool de SaucerSwap por poolId.
        Ejemplo de respuesta incluye: fee, sqrtRatioX96, tickCurrent, liquidity, tokenA/B, etc.
        """
        import requests
        if pool_id is None:
            raise ValueError("pool_id es obligatorio")
        pid = str(pool_id)
        url = self.config.api_base.rstrip("/") + f"/v2/pools/{pid}"
        headers = {"x-api-key": self.api_key, "Accept": "application/json", "User-Agent": "LiquidityProvider/1.0"}
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, dict) else {"data": data}

    def get_pool_state_decoded(self, pool_id: Union[int, str]) -> Dict[str, Any]:
        """Normaliza el estado de la pool al formato común esperado por el planificador/tools.
        Campos clave: tick_current_index, sqrtRatioX96, liquidity, fee, token0/token1.
        """
        info = self.get_pool_info(pool_id) or {}
        # tick actual
        tick_raw = info.get("tickCurrent") if isinstance(info, dict) else None
        if tick_raw is None:
            tick_raw = info.get("tick") if isinstance(info, dict) else None
        try:
            tick_current = int(tick_raw) if tick_raw is not None else 0
        except Exception:
            tick_current = 0
        # liquidity puede venir como str grande en algunas APIs
        liq = info.get("liquidity") if isinstance(info, dict) else None
        try:
            liquidity = int(liq) if liq is not None and str(liq).isdigit() else liq
        except Exception:
            liquidity = liq
        # Tokens: aceptar tanto token0/1 como tokenA/B y exponer ambos alias en la salida
        t0 = (info.get("token0") if isinstance(info, dict) else None) or (info.get("tokenA") if isinstance(info, dict) else None) or {}
        t1 = (info.get("token1") if isinstance(info, dict) else None) or (info.get("tokenB") if isinstance(info, dict) else None) or {}

        out: Dict[str, Any] = {
            "protocol": "saucerswap",
            "pool_id": str(pool_id),
            "tick_current_index": tick_current,
            "sqrtRatioX96": info.get("sqrtRatioX96") if isinstance(info, dict) else None,
            "liquidity": liquidity,
            "fee": info.get("fee") if isinstance(info, dict) else None,
            "token0": t0,
            "token1": t1,
            "tokenA": t0,
            "tokenB": t1,
            # placeholder de sigma_ticks hasta tener cálculo de volatilidad real
            "sigma_ticks": 10,
        }
        return out

    def get_pool_state_enriched(self, pool_id: Union[int, str]) -> Dict[str, Any]:
        """Devuelve estado enriquecido con alias token0/1 y tokenA/B, asegurando decimales (int) y priceUsd (float)."""
        st = self.get_pool_state_decoded(pool_id) or {}
        if not isinstance(st, dict):
            return {"value": st}
        # Asegurar alias y tipos
        def _coerce_token(tok: Dict[str, Any]) -> Dict[str, Any]:
            t = dict(tok or {})
            if "decimals" in t:
                try:
                    t["decimals"] = int(t.get("decimals") or 0)
                except Exception:
                    t["decimals"] = 0
            if "priceUsd" in t:
                try:
                    t["priceUsd"] = float(t.get("priceUsd") or 0.0)
                except Exception:
                    t["priceUsd"] = 0.0
            return t
        t0 = _coerce_token(st.get("token0") or st.get("tokenA") or {})
        t1 = _coerce_token(st.get("token1") or st.get("tokenB") or {})
        # Marcar WHBAR
        try:
            wh_evm = self._get_whbar_evm_from_router() or ""
            wh_hts = self._evm_to_hts(wh_evm) or ""
            id0 = str((t0.get("id") or "")).strip()
            id1 = str((t1.get("id") or "")).strip()
            evm0 = str((t0.get("evm") or t0.get("tokenEvm") or "")).strip()
            evm1 = str((t1.get("evm") or t1.get("tokenEvm") or "")).strip()
            t0["isWhbar"] = (id0 == wh_hts) or (evm0.lower() == (wh_evm or "").lower())
            t1["isWhbar"] = (id1 == wh_hts) or (evm1.lower() == (wh_evm or "").lower())
        except Exception:
            t0.setdefault("isWhbar", False)
            t1.setdefault("isWhbar", False)
        st["token0"] = t0
        st["token1"] = t1
        st["tokenA"] = t0
        st["tokenB"] = t1
        return st

    def liquidity_prepare_open(
        self,
        pool_id: Union[int, str],
        tick_lower: int,
        tick_upper: int,
        mintA: str,
        mintB: str,
        amount0_desired: int = 0,
        amount1_desired: int = 0,
        user_token_account_a: Optional[str] = None,
        user_token_account_b: Optional[str] = None,
        slippage_bps: int = 100,
        with_metadata: bool = True,
        base_flag: Optional[bool] = False,
    ) -> Dict[str, Any]:
        """Wrapper para cumplir la interfaz común de open_position en SaucerSwap.
        Construye quote por ticks y prepara la transacción de mint (liquidity_prepare).
        Las cuentas de usuario no son necesarias aquí (modelo EVM); los montos máximos se infieren via quote.
        """
        # Determinar fee_bps, tickSpacing y orden token0/token1 desde la pool
        info = self.get_pool_info(pool_id)
        fee_bps = int(info.get("fee", 0)) if isinstance(info, dict) else 0
        # Resolver tickSpacing desde contrato si la API no lo expone
        tick_spacing = 1
        try:
            if isinstance(info, dict):
                tick_spacing = int(info.get("tickSpacing") or info.get("tick_spacing") or 0) or 0
            if tick_spacing <= 0:
                pool_contract_id = (info.get("contractId") or info.get("contract_id") or "") if isinstance(info, dict) else ""
                pool_evm = self._hts_to_evm(pool_contract_id) if pool_contract_id else ""
                if pool_evm and pool_evm.startswith("0x"):
                    import eth_utils  # type: ignore
                    sel = eth_utils.keccak(text="tickSpacing()")[:4]
                    data = "0x" + sel.hex()
                    res = self._call_rpc("eth_call", [{"to": pool_evm, "data": data}, "latest"]) or "0x0"
                    # Decodificar int24 desde uint256 devuelto
                    tick_spacing = int(res, 16)
            if tick_spacing <= 0:
                tick_spacing = 1
        except Exception:
            tick_spacing = 1
        t0 = (info.get("token0") or {}) if isinstance(info, dict) else {}
        t1 = (info.get("token1") or {}) if isinstance(info, dict) else {}
        raw_id0 = t0.get("id") or t0.get("tokenId")
        raw_id1 = t1.get("id") or t1.get("tokenId")
        evm0 = t0.get("evm") or t0.get("tokenEvm")
        evm1 = t1.get("evm") or t1.get("tokenEvm")
        # Normalizar a HTS para comparar de forma estable
        def norm_hts(x: Optional[str]) -> str:
            try:
                if not isinstance(x, str):
                    return ""
                if x.upper() == "HBAR":
                    return self._whbar_token_id() or ""
                if x.count(".") == 2:
                    return x
                if x.startswith("0x"):
                    return self._evm_to_hts(x) or ""
                return x
            except Exception:
                return ""
        # Preferir derivación on-chain desde el contrato de pool (token0()/token1())
        id0 = None
        id1 = None
        try:
            pool_contract_id = (info.get("contractId") or info.get("contract_id") or "") if isinstance(info, dict) else ""
            pool_evm = self._hts_to_evm(pool_contract_id) if pool_contract_id else ""
            if isinstance(pool_evm, str) and pool_evm.startswith("0x"):
                import eth_utils  # type: ignore
                from eth_abi import decode as abi_decode  # type: ignore
                sel_t0 = eth_utils.keccak(text="token0()")[:4]
                sel_t1 = eth_utils.keccak(text="token1()")[:4]
                r0 = self._call_rpc("eth_call", [{"to": pool_evm, "data": "0x" + sel_t0.hex()}, "latest"]) or "0x"
                r1 = self._call_rpc("eth_call", [{"to": pool_evm, "data": "0x" + sel_t1.hex()}, "latest"]) or "0x"
                addr0 = abi_decode(["address"], bytes.fromhex(r0[2:]))[0]
                addr1 = abi_decode(["address"], bytes.fromhex(r1[2:]))[0]
                id0 = self._evm_to_hts(addr0) or ""
                id1 = self._evm_to_hts(addr1) or ""
        except Exception:
            id0 = None
            id1 = None
        # Si falló on-chain, caer al info normalizado
        if not id0 or not id1:
            id0 = norm_hts(raw_id0) or norm_hts(evm0)
            id1 = norm_hts(raw_id1) or norm_hts(evm1)
        mintA_hts = norm_hts(mintA)
        mintB_hts = norm_hts(mintB)
        # Alinear estrictamente al orden token0/token1 de la pool.
        # Si el caller los pasó invertidos, reordenamos y marcaremos swap de amounts.
        swap_amounts = False
        if mintA_hts == id0 and mintB_hts == id1:
            tokenA = id0
            tokenB = id1
            use_evmA, use_evmB = evm0, evm1
        elif mintA_hts == id1 and mintB_hts == id0:
            tokenA = id0
            tokenB = id1
            use_evmA, use_evmB = evm0, evm1
            swap_amounts = True
        else:
            raise RuntimeError("mints no coinciden con token0/token1 de la pool")

        # Alinear ticks al tickSpacing del pool y asegurar rango válido
        try:
            def snap_down(x: int, s: int) -> int:
                return (int(x) // s) * s
            def snap_up(x: int, s: int) -> int:
                return ((int(x) + s - 1) // s) * s
            lo = snap_down(int(tick_lower), tick_spacing)
            hi = snap_up(int(tick_upper), tick_spacing)
            if hi <= lo:
                hi = lo + tick_spacing
            # Clamp a los límites de Uniswap v3 (±887272) ajustados al spacing
            try:
                min_tick = snap_up(-887272, tick_spacing)
                max_tick = snap_down(887272, tick_spacing)
                if lo < min_tick:
                    lo = min_tick
                if hi > max_tick:
                    hi = max_tick
                if hi <= lo:
                    hi = lo + tick_spacing
            except Exception:
                pass
            tick_lower = lo
            tick_upper = hi
        except Exception:
            pass

        # Cantidades deseadas: usar balances actuales como upper bound, por simplicidad 50/50 = 0 (la pool decide)
        # Para un mínimo viable, dejamos amounts deseados en 0 y que el contrato determine consumo según msg.value/allowances.
        # Si se pasan amounts deseados, respetarlos; si no, defaults a 0
        amount0_desired = int(amount0_desired or 0)
        amount1_desired = int(amount1_desired or 0)
        if swap_amounts:
            amount0_desired, amount1_desired = amount1_desired, amount0_desired

        # Usar slippage de entrada; los mínimos se fuerzan a 0 en mint
        eff_slippage_bps = int(slippage_bps or 0)
        quote = self.liquidity_quote_by_ticks(
            tokenA=tokenA,
            tokenB=tokenB,
            fee_bps=fee_bps,
            tick_lower=int(tick_lower),
            tick_upper=int(tick_upper),
            amount0_desired=amount0_desired,
            amount1_desired=amount1_desired,
            slippage_bps=eff_slippage_bps,
        )
        # Reordenar amounts si fuese necesario para coincidir con token0/token1 del pool
        try:
            q = quote or {}
            qa0 = int(q.get("amounts", {}).get("amount0Desired", 0))
            qa1 = int(q.get("amounts", {}).get("amount1Desired", 0))
            # Si los mints originales venían invertidos, aseguramos amounts en el orden token0/token1
            # Nota: liquidity_quote_by_ticks ya debería devolver en orden del pool; esto es redundante por seguridad
            _ = qa0 + qa1  # no-op, marcador de uso
        except Exception:
            pass
        prep = self.liquidity_prepare(quote, deadline_s=300)
        return prep

    def _strip_fields(self, pos: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = dict(pos)
        for key in ("token0", "token1"):
            tok = cleaned.get(key)
            if isinstance(tok, dict):
                tok = dict(tok)
                tok.pop("description", None)
                tok.pop("icon", None)
                tok.pop("website", None)
                cleaned[key] = tok
        return cleaned

    def check_position_exists_tool(self, serial: int) -> Dict[str, Any]:
        if serial is None:
            return {"exists": False, "details": {"reason": "missing serial"}}
        try:
            positions = self._saucerswap_positions(self.account_id)
        except Exception as exc:
            return {"exists": False, "details": {"error": f"saucerswap api failed: {exc}"}}
        for pos in positions:
            try:
                if int(pos.get("tokenSN")) == int(serial):
                    return {"exists": True, "details": self._strip_fields(pos)}
            except Exception:
                continue
        return {"exists": False, "details": {}}

    # ---------------- JSON-RPC helpers ----------------
    def _call_rpc(self, method: str, params: List[Any]) -> Any:
        import requests
        last_err: Optional[Exception] = None
        for _ in range(len(self.config.json_rpc_endpoints) or 1):
            url = self.rpc.current
            try:
                if self.logger.isEnabledFor(logging.DEBUG):
                    try:
                        self.logger.debug("RPC call -> %s %s params=%s", url, method, json.dumps(params)[:2000])
                    except Exception:
                        self.logger.debug("RPC call -> %s %s (params non-serializable)", url, method)
                r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=20)
                try:
                    r.raise_for_status()
                except requests.HTTPError as http_exc:  # type: ignore
                    # Intenta incluir el cuerpo de error si viene JSON o texto
                    body = None
                    try:
                        body = r.json()
                    except Exception:
                        body = r.text
                    if self.logger.isEnabledFor(logging.WARNING):
                        self.logger.warning("RPC HTTP error (%s): %s body=%s", url, http_exc, body)
                    last_err = RuntimeError(f"HTTP {r.status_code}: {http_exc} body={body}")
                    raise last_err
                data = r.json()
                if self.logger.isEnabledFor(logging.DEBUG):
                    try:
                        self.logger.debug("RPC result <- %s %s result=%s", url, method, json.dumps(data)[:2000])
                    except Exception:
                        self.logger.debug("RPC result <- %s %s (non-serializable)", url, method)
                if "error" in data:
                    if self.logger.isEnabledFor(logging.WARNING):
                        self.logger.warning("RPC error payload (%s): %s", url, data.get("error"))
                    raise RuntimeError(data["error"])
                return data.get("result")
            except Exception as exc:
                last_err = exc
                self.logger.warning("RPC failed (%s): %s", url, exc)
                self.rpc.rotate()
        raise RuntimeError(f"All JSON-RPC endpoints failed: {last_err}")

    def _hts_to_evm(self, id_str: str) -> str:
        # Convierte 0.0.x a 0x… (20 bytes). Hedera usa ContractId/TokenId mapping.
        parts = id_str.split(".")
        if len(parts) != 3:
            return id_str  # asume ya 0x…
        shard, realm, num = int(parts[0]), int(parts[1]), int(parts[2])
        evm_int = (shard << (8*16)) | (realm << (8*8)) | num
        return "0x" + evm_int.to_bytes(20, byteorder="big").hex()

    def _evm_to_hts(self, evm_addr: str) -> Optional[str]:
        """Convierte 0x.. (20 bytes) a formato HTS shard.realm.num, si aplica."""
        try:
            hexstr = evm_addr.lower().replace("0x", "")
            evm_int = int(hexstr, 16)
            shard = evm_int >> (8 * 16)
            realm = (evm_int >> (8 * 8)) & ((1 << 64) - 1)
            num = evm_int & ((1 << 64) - 1)
            return f"{shard}.{realm}.{num}"
        except Exception:
            return None

    def _resolve_contract_hts_via_mirror(self, evm_addr: str) -> Optional[str]:
        """Resuelve el ContractId (0.0.x) desde un address EVM usando Mirror Node."""
        try:
            import requests
            url = f"https://mainnet.mirrornode.hedera.com/api/v1/contracts/{evm_addr}"
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            data = r.json()
            cid = data.get("contract_id")
            return cid if isinstance(cid, str) and cid.count(".") == 2 else None
        except Exception:
            return None

    def _encode_path_v2(self, tokens: List[str], fees_bps: List[int]) -> bytes:
        if len(tokens) < 2 or len(fees_bps) != len(tokens) - 1:
            raise ValueError("path inválido: tokens y fees no casan")
        out = bytearray()
        for i, t in enumerate(tokens):
            t_clean = t.lower()
            if t_clean.startswith("0x"):
                t_clean = t_clean[2:]
            out += bytes.fromhex(t_clean.zfill(40))
            if i < len(fees_bps):
                fee = fees_bps[i]
                if not (0 <= fee <= 0xFFFFFF):
                    raise ValueError("fee fuera de rango")
                out += fee.to_bytes(3, byteorder="big")
        return bytes(out)

    # ---------------- Quote ----------------
    def get_quote(self, token_in: str, token_out: str, amount: int, kind: str, fee_bps: int, route_hops: Optional[List[Tuple[str,int]]] = None) -> Dict[str, Any]:
        from eth_abi import encode as abi_encode  # type: ignore
        from eth_abi import decode as abi_decode  # type: ignore
        import eth_utils  # type: ignore

        route_hops = route_hops or []
        # WHBAR se resuelve del router ABI, no del YAML
        whbar = self._get_whbar_evm_from_router()
        def norm(t: str) -> str:
            if t.upper() == "HBAR":
                if not whbar or not whbar.startswith("0x"):
                    raise ValueError("WHBAR no disponible desde router")
                return whbar
            return self._hts_to_evm(t)

        tokens = [norm(token_in)] + [norm(t) for (t, _f) in route_hops] + [norm(token_out)]
        fees = [fee_bps] + [f for (_t, f) in route_hops]
        path = self._encode_path_v2(tokens, fees)
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("get_quote: kind=%s amount=%s tokens=%s fees=%s", kind, amount, tokens, fees)

        quoter = self._hts_to_evm(self.config.contracts.get("quoter_v2", ""))
        if not quoter.startswith("0x"):
            raise ValueError("quoter_v2 no configurado correctamente")

        # Preferimos construir selector desde ABI si está presente
        self._ensure_quoter_abi_loaded()
        if kind == "exact_in":
            entry = self._abi_find_function(self._quoter_abi, "quoteExactInput", ["bytes", "uint256"]) or {}
            selector = self._abi_selector_from_entry(entry) or eth_utils.keccak(text="quoteExactInput(bytes,uint256)")[:4]
            calldata = selector + abi_encode(["bytes", "uint256"], [path, amount])
        elif kind == "exact_out":
            entry = self._abi_find_function(self._quoter_abi, "quoteExactOutput", ["bytes", "uint256"]) or {}
            selector = self._abi_selector_from_entry(entry) or eth_utils.keccak(text="quoteExactOutput(bytes,uint256)")[:4]
            tokens_rev = list(reversed(tokens))
            fees_rev = list(reversed(fees))
            path_rev = self._encode_path_v2(tokens_rev, fees_rev)
            calldata = selector + abi_encode(["bytes", "uint256"], [path_rev, amount])
        else:
            raise ValueError("kind debe ser 'exact_in' o 'exact_out'")

        result = self._call_rpc("eth_call", [{"to": quoter, "data": "0x" + calldata.hex()}, "latest"])
        # Intentar decodificar outputs desde ABI si disponible
        out_types = self._abi_output_types(self._abi_find_function(self._quoter_abi, "quoteExactInput" if kind == "exact_in" else "quoteExactOutput", ["bytes", "uint256"]))
        if out_types == ["uint256", "uint160[]", "uint32[]", "uint256"] or out_types is None:
            decoded = abi_decode(["uint256", "uint160[]", "uint32[]", "uint256"], bytes.fromhex(result[2:]))
        else:
            decoded = abi_decode(out_types, bytes.fromhex(result[2:]))
        out = {
            ("amountOut" if kind == "exact_in" else "amountIn"): int(decoded[0]),
            "sqrtPriceX96AfterList": [int(x) for x in decoded[1]],
            "initializedTicksCrossedList": [int(x) for x in decoded[2]],
            "gasEstimate": int(decoded[3]),
            "path": "0x" + (path.hex() if kind == "exact_in" else path_rev.hex()),
            # metadata necesaria para swap_prepare (comportamiento homogéneo con Raydium)
            "kind": kind,
            "tokenInRaw": token_in,
            "tokenOutRaw": token_out,
            "requestedAmount": int(amount),
            "feeBps": int(fee_bps),
            "routeHops": route_hops or [],
        }
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("get_quote: %s -> %s result=%s", token_in, token_out, {k: out[k] for k in ("amountOut","amountIn","gasEstimate") if k in out})
        return out

    # ---------------- Collect fees/rewards (position) ----------------
    def collect_rewards(self, pool_id: str, position_id: Union[int, str]) -> Dict[str, Any]:
        """Colecciona las fees/rewards acumuladas de una posición (serial HTS) hacia la wallet (owner).
        Implementado vía NonfungiblePositionManager.collect para token0 y token1.
        """
        try:
            from eth_abi import encode as abi_encode  # type: ignore
            import eth_utils  # type: ignore
        except Exception as exc:
            return {"ok": False, "error": f"faltan dependencias eth_abi/eth_utils: {exc}"}

        self._ensure_npm_abi_loaded()
        npm = self._get_npm_address_evm()
        if not npm:
            return {"ok": False, "error": "nonfungible_position_manager no configurado"}

        owner = self.evm_address
        try:
            serial = int(position_id)
        except Exception:
            return {"ok": False, "error": "position inválida (serial)"}

        # collect(uint256,address,uint128,uint128) selector 0xfc6f7865
        sel_collect = bytes.fromhex("fc6f7865")
        max_u128 = (1 << 128) - 1
        col0 = sel_collect + abi_encode(["uint256", "address", "uint128", "uint128"], [serial, owner, max_u128, 0])
        col1 = sel_collect + abi_encode(["uint256", "address", "uint128", "uint128"], [serial, owner, 0, max_u128])

        # multicall(bytes[])
        entry_mc = self._abi_find_function(self._npm_abi, "multicall", ["bytes[]"]) or {}
        sel_mc = self._abi_selector_from_entry(entry_mc) or eth_utils.keccak(text="multicall(bytes[])")[:4]
        calldata = sel_mc + abi_encode(["bytes[]"], [[col0, col1]])

        tx = {"from": owner, "to": npm, "data": "0x" + calldata.hex()}
        try:
            gas_estimate = self._call_rpc("eth_estimateGas", [tx, "latest"])  # may raise
            if isinstance(gas_estimate, str):
                gas_estimate = int(gas_estimate, 16)
            tx["gas"] = int(gas_estimate) or 1_000_000
        except Exception:
            tx["gas"] = 1_000_000

        res = self.send_transaction(tx, wait=True)
        # Intentar extraer amount0/amount1 desde los logs del receipt usando el contrato de pool
        amount0: Optional[int] = None
        amount1: Optional[int] = None
        try:
            # Resolver poolId del serial
            pos = None
            try:
                for p in self._saucerswap_positions(self.account_id):
                    if int(p.get("tokenSN")) == int(serial):
                        pos = p; break
            except Exception:
                pos = None
            pid = None
            if pos:
                pid = pos.get("poolId") or pos.get("pool_id") or ((pos.get("pool") or {}).get("id"))
            pool_evm = None
            if pid is not None:
                info = self.get_pool_info(int(pid)) or {}
                pool_evm = info.get("contractAddress") or info.get("contract_address")
            # Parseo de logs: buscar eventos del contrato de pool y tomar las dos últimas palabras como amounts
            logs = (((res or {}).get("receipt") or {}).get("logs") or [])
            for lg in logs:
                try:
                    if pool_evm and str(lg.get("address", "")).lower() != str(pool_evm).lower():
                        continue
                    data_hex = lg.get("data") or "0x"
                    if not (isinstance(data_hex, str) and data_hex.startswith("0x")):
                        continue
                    raw = bytes.fromhex(data_hex[2:])
                    # Necesitamos al menos 64 bytes para amount0/amount1 (uint128 cada uno ocupa 16 bytes, pero ABI words son 32)
                    if len(raw) >= 64:
                        # Tomar las últimas dos words (64 bytes) como amounts potenciales
                        w1 = int.from_bytes(raw[-32:], byteorder="big", signed=False)
                        w0 = int.from_bytes(raw[-64:-32], byteorder="big", signed=False)
                        # Heurística: si alguno es cero, mantener el otro; acumular si múltiples logs
                        amount0 = (0 if amount0 is None else amount0) + (w0 or 0)
                        amount1 = (0 if amount1 is None else amount1) + (w1 or 0)
                    elif len(raw) >= 32:
                        # Un único amount (algunas rutas emiten un solo valor)
                        v = int.from_bytes(raw[-32:], byteorder="big", signed=False)
                        # A falta de contexto, asumir token0
                        amount0 = (0 if amount0 is None else amount0) + v
                except Exception:
                    continue
        except Exception:
            pass
        result = {"collect": res}
        if amount0 is not None or amount1 is not None:
            result["amounts"] = {"amount0": amount0 or 0, "amount1": amount1 or 0}
        return {"ok": True, "result": result}

    # ---------------- Swap (preparación) ----------------
    def swap_prepare(self, swap_quote: Dict[str, Any], slippage_bps: int = 50, deadline_s: int = 300, recipient_evm: Optional[str] = None) -> Dict[str, Any]:
        from eth_abi import encode as abi_encode  # type: ignore
        import eth_utils  # type: ignore
        import time

        if not isinstance(swap_quote, dict):
            raise ValueError("swap_quote inválido: se espera el resultado de get_quote")
        kind = swap_quote.get("kind")
        if kind not in ("exact_in", "exact_out"):
            raise ValueError("swap_quote.kind debe ser 'exact_in' o 'exact_out'")
        path_hex = swap_quote.get("path")
        if not isinstance(path_hex, str) or not path_hex.startswith("0x"):
            raise ValueError("swap_quote.path inválido")

        # Cantidades y tokens según el tipo de cotización
        requested_amount = int(swap_quote.get("requestedAmount"))
        amount_out = swap_quote.get("amountOut")
        amount_in = swap_quote.get("amountIn")
        token_in_raw = str(swap_quote.get("tokenInRaw"))
        token_out_raw = str(swap_quote.get("tokenOutRaw"))

        is_hbar_in = token_in_raw.upper() == "HBAR"
        is_hbar_out = token_out_raw.upper() == "HBAR"

        sender = recipient_evm or self.evm_address
        recipient = recipient_evm or sender
        router = self._hts_to_evm(self.config.contracts.get("swap_router", ""))
        if not router.startswith("0x"):
            raise ValueError("swap_router no configurado correctamente")

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("swap_prepare: kind=%s tokenIn=%s tokenOut=%s requested=%s", kind, token_in_raw, token_out_raw, requested_amount)

        if kind == "exact_in":
            if amount_out is None:
                raise ValueError("swap_quote.amountOut ausente para exact_in")
            min_out = (int(amount_out) * (10000 - slippage_bps)) // 10000
        else:
            if amount_in is None:
                raise ValueError("swap_quote.amountIn ausente para exact_out")
            max_in = (int(amount_in) * (10000 + slippage_bps)) // 10000

        value = 0
        tx_data = None

        # Auto-asociación HTS si token_out no está asociado (cuando no es HBAR)
        association: Optional[Dict[str, Any]] = None
        associated: Optional[bool] = None
        notes: List[str] = []
        if not is_hbar_out:
            # Soportar tanto HTS (0.0.x) como EVM (0x...) derivando el ID HTS si es necesario
            try:
                token_out_hts = token_out_raw if (isinstance(token_out_raw, str) and token_out_raw.count(".") == 2) else (self._evm_to_hts(token_out_raw) or "")
            except Exception:
                token_out_hts = ""
            if isinstance(token_out_hts, str) and token_out_hts.count(".") == 2:
                try:
                    chk = self.check_associated(token_out_hts)
                    associated = bool(chk.get("associated"))
                    if not chk.get("associated"):
                        assoc_res = self.associate_execute(token_out_hts)
                        association = assoc_res
                        if not assoc_res.get("executed"):
                            notes.append(f"auto-association failed: {assoc_res}")
                        else:
                            notes.append("auto-association executed")
                except Exception as exc:
                    notes.append(f"auto-association error: {exc}")

        # Auto-approve si token_in es ERC20 (no HBAR): allowance >= needed
        approve_tx: Optional[Dict[str, Any]] = None
        allowance_current: Optional[int] = None
        allowance_needed: Optional[int] = None
        if not is_hbar_in:
            try:
                needed = (max_in if kind == "exact_out" else requested_amount)
                alw = self.allowance_check(token_in_raw)
                current = int(alw.get("allowance", 0))
                allowance_current = current
                allowance_needed = int(needed)
                if current < int(needed):
                    # Intentar primero vía HTS SDK (requiere IDs HTS, no EVM)
                    token_id_hts = token_in_raw if (isinstance(token_in_raw, str) and token_in_raw.count(".") == 2) else (self._evm_to_hts(token_in_raw) or "")
                    spender_hts = self._evm_to_hts(router) or ""
                    did_approve = False
                    if token_id_hts and spender_hts:
                        try:
                            res_hts = self.approve_hts_execute(token_id=token_id_hts, spender_contract_id=spender_hts)
                            notes.append(f"approve HTS ejecutado: {res_hts}")
                            did_approve = bool(res_hts.get("executed"))
                        except Exception as exc:
                            notes.append(f"approve HTS error: {exc}")
                            did_approve = False
                    if not did_approve:
                        raise RuntimeError("approve HTS no ejecutado; abortando swap")
                    # Poll corto para ver el nuevo allowance tras cualquiera de las vías
                    try:
                        import time
                        for _ in range(20):
                            time.sleep(1)
                            new_alw = self.allowance_check(token_in_raw)
                            current = int(new_alw.get("allowance", 0))
                            if current >= int(needed):
                                break
                        allowance_current = current
                    except Exception:
                        pass
            except Exception as exc:
                notes.append(f"auto-approve HTS error: {exc}")

        # Deadline absoluto (epoch seconds)
        deadline_ts = int(time.time()) + int(os.environ.get("SWAP_DEADLINE_S", str(deadline_s)))

        if kind == "exact_in":
            # exactInput((bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum))
            exact_sel = eth_utils.keccak(text="exactInput((bytes,address,uint256,uint256,uint256))")[:4]
            args_tuple = (
                bytes.fromhex(path_hex[2:]),
                recipient,
                int(deadline_ts),
                int(requested_amount),
                int(min_out),
            )
            exact_calldata = exact_sel + abi_encode(["(bytes,address,uint256,uint256,uint256)"], [args_tuple])
            if is_hbar_in:
                # multicall(bytes[]) with [ exactInput(...), refundETH() ]
                refund_sel = eth_utils.keccak(text="refundETH()")[:4]
                multicall_sel = eth_utils.keccak(text="multicall(bytes[])")[:4]
                inner = [exact_calldata, refund_sel]
                tx_data = multicall_sel + abi_encode(["bytes[]"], [inner])
                # amount está en tinybars (8 decimales). JSON-RPC espera wei (1 tinybar = 1e10 wei)
                value = int(requested_amount) * (10 ** 10)
            elif is_hbar_out:
                # Token -> HBAR: unwrap WHBAR to HBAR after swap y reembolsa residual de HBAR
                unwrap_sel = eth_utils.keccak(text="unwrapWHBAR(uint256,address)")[:4]
                # amountMinimum=0 to unwrap all received WHBAR balance
                unwrap_calldata = unwrap_sel + abi_encode(["uint256", "address"], [0, recipient])
                refund_sel = eth_utils.keccak(text="refundETH()")[:4]
                multicall_sel = eth_utils.keccak(text="multicall(bytes[])")[:4]
                inner = [exact_calldata, unwrap_calldata, refund_sel]
                tx_data = multicall_sel + abi_encode(["bytes[]"], [inner])
            else:
                tx_data = exact_calldata
        else:
            # exactOutput((bytes path, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum))
            exacto_sel = eth_utils.keccak(text="exactOutput((bytes,address,uint256,uint256,uint256))")[:4]
            # amountOut debe ser el objetivo solicitado por el usuario (amount)
            args_tuple = (
                bytes.fromhex(path_hex[2:]),
                recipient,
                int(deadline_ts),
                int(requested_amount),
                int(max_in),
            )
            exacto_calldata = exacto_sel + abi_encode(["(bytes,address,uint256,uint256,uint256)"], [args_tuple])
            if is_hbar_in:
                # HBAR -> Token (exact_out): pagar con value y reembolsar sobrante
                refund_sel = eth_utils.keccak(text="refundETH()")[:4]
                multicall_sel = eth_utils.keccak(text="multicall(bytes[])")[:4]
                inner = [exacto_calldata, refund_sel]
                tx_data = multicall_sel + abi_encode(["bytes[]"], [inner])
                value = int(max_in) * (10 ** 10)
            elif is_hbar_out:
                # Token -> HBAR (exact_out): unwrap WHBAR to HBAR after swap y reembolsa residual
                unwrap_sel = eth_utils.keccak(text="unwrapWHBAR(uint256,address)")[:4]
                # amountMinimum=0 to unwrap all received WHBAR balance (target exact_out already enforced by router)
                unwrap_calldata = unwrap_sel + abi_encode(["uint256", "address"], [0, recipient])
                refund_sel = eth_utils.keccak(text="refundETH()")[:4]
                multicall_sel = eth_utils.keccak(text="multicall(bytes[])")[:4]
                inner = [exacto_calldata, unwrap_calldata, refund_sel]
                tx_data = multicall_sel + abi_encode(["bytes[]"], [inner])
            else:
                tx_data = exacto_calldata

        tx = {"from": sender, "to": router, "data": "0x" + tx_data.hex()}
        if value:
            tx["value"] = hex(value)
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("swap_prepare: to=%s value=%s data.len=%s", router, tx.get("value"), len(tx["data"]))

        gas_estimate: Optional[int] = None
        try:
            gas = self._call_rpc("eth_estimateGas", [tx, "latest"])
            gas_estimate = int(gas, 16) if isinstance(gas, str) else gas
        except Exception as exc:
            notes.append("eth_estimateGas revert: verificar asociación HTS del token_out, allowance si aplica y uso de multicall para HBAR")
            self.logger.warning("eth_estimateGas failed: %s", exc)

        out = {
            "to": router,
            "data": "0x" + tx_data.hex(),
            "value": value,
            "gasEstimate": gas_estimate,
            "quote": swap_quote,
            "from": sender,
            "notes": notes,
            "association": association,
            "associated": associated,
            "allowance": {
                "current": allowance_current,
                "needed": allowance_needed,
            } if not is_hbar_in else None,
            "approve": approve_tx,
        }
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("swap_prepare: gasEstimate=%s association=%s allowance=%s", gas_estimate, bool(association), (out.get("allowance") or {}))
        return out

    # ---------------- Envío de transacciones ----------------
    def _get_chain_id(self) -> int:
        try:
            res = self._call_rpc("eth_chainId", [])
            return int(res, 16) if isinstance(res, str) else int(res)
        except Exception:
            # Hedera mainnet chainId 295
            return 295

    def _get_nonce(self, address: str) -> int:
        res = self._call_rpc("eth_getTransactionCount", [address, "pending"])
        return int(res, 16)

    def _suggest_fees(self) -> Dict[str, int]:
        # Hedera: forzamos legacy gasPrice y mínimo 1 tinybar (10_000_000_000 wei)
        min_wei = 10_000_000_000
        base = None
        try:
            gp = self._call_rpc("eth_gasPrice", [])
            base = int(gp, 16)
        except Exception:
            base = None
        gas_price = base if base is not None else min_wei
        if gas_price < min_wei:
            gas_price = min_wei
        return {"gasPrice": gas_price}

    def send_transaction(self, tx: Dict[str, Any], wait: bool = True, timeout_s: int = 120, poll_s: float = 2.0) -> Dict[str, Any]:
        try:
            from eth_account import Account  # type: ignore
            from eth_utils import to_checksum_address  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Falta eth_account para firmar: {exc}")

        address_from = tx.get("from") or self.evm_address
        chain_id = self._get_chain_id()
        nonce = self._get_nonce(address_from)
        fees = self._suggest_fees()
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("send_tx: from=%s to=%s chainId=%s nonce=%s", address_from, tx.get("to"), chain_id, nonce)

        # Construir tx a firmar
        tx_to_sign: Dict[str, Any] = {
            "to": to_checksum_address(tx["to"]) if isinstance(tx.get("to"), str) and tx["to"].startswith("0x") else tx.get("to"),
            "data": tx.get("data", "0x"),
            "nonce": nonce,
            "chainId": chain_id,
        }
        if "gas" in tx:
            tx_to_sign["gas"] = tx["gas"]
        if "value" in tx:
            # value puede venir en hex o int
            val = tx["value"]
            tx_to_sign["value"] = int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)
        # fees
        # Forzamos legacy en Hedera
        tx_to_sign.update({"gasPrice": fees["gasPrice"]})
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("send_tx: gasPrice=%s gas(pre)=%s value=%s", tx_to_sign.get("gasPrice"), tx_to_sign.get("gas"), tx_to_sign.get("value"))

        # Si falta gas, intenta estimar
        if "gas" not in tx_to_sign:
            est = self._call_rpc("eth_estimateGas", [{"from": address_from, "to": tx["to"], "data": tx_to_sign["data"], "value": hex(tx_to_sign.get("value", 0)) if tx_to_sign.get("value") else "0x0"}, "latest"])
            tx_to_sign["gas"] = int(est, 16) if isinstance(est, str) else est

        # Firmar y enviar
        acct = Account.from_key(bytes.fromhex(self._private_key_hex))
        signed = acct.sign_transaction(tx_to_sign)
        raw_hex = signed.rawTransaction.hex()
        payload = raw_hex if isinstance(raw_hex, str) and raw_hex.startswith("0x") else ("0x" + raw_hex)
        tx_hash = self._call_rpc("eth_sendRawTransaction", [payload])
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("send_tx: hash=%s", tx_hash)
        out: Dict[str, Any] = {"txHash": tx_hash}

        if wait:
            import time
            deadline = time.time() + timeout_s
            receipt = None
            while time.time() < deadline:
                try:
                    rec = self._call_rpc("eth_getTransactionReceipt", [tx_hash])
                    if rec:
                        # Adjuntar decodificación de revert si aplica
                        if rec.get("status") in ("0x0", 0):
                            # Hedera incluye revertReason en algunos casos
                            rv = rec.get("revertReason")
                            if rv:
                                decoded = self._decode_revert_data(rv)
                                rec["revertDecoded"] = decoded
                                if self.logger.isEnabledFor(logging.WARNING):
                                    self.logger.warning("send_tx: receipt revert status with reason=%s decoded=%s", rv, decoded)
                        receipt = rec
                        break
                except Exception:
                    pass
                time.sleep(poll_s)
            out["receipt"] = receipt
            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info("send_tx: receipt status=%s gasUsed=%s", (receipt or {}).get("status"), (receipt or {}).get("gasUsed"))
        return out

    def swap_send(self, prep: Dict[str, Any], wait: bool = True) -> Dict[str, Any]:
        results: Dict[str, Any] = {"steps": []}
        # 1) approve si existe
        approve = prep.get("approve")
        if approve:
            txa = {"from": approve.get("from") or self.evm_address, "to": approve["to"], "data": approve["data"]}
            res_a = self.send_transaction(txa, wait=wait)
            results["steps"].append({"approve": res_a})
        # 2) swap
        txs = {"from": prep.get("from") or self.evm_address, "to": prep["to"], "data": prep["data"]}
        if prep.get("value"):
            txs["value"] = prep["value"]
        res_s = self.send_transaction(txs, wait=wait)
        results["steps"].append({"swap": res_s})
        # 3) Barrido WHBAR obligatorio (post-swap residual) mediante helper dedicado
        try:
            owner = prep.get("from") or self.evm_address
            sweep = self._whbar_sweep_unwrap(owner)
            if sweep and (sweep.get("executed") or sweep.get("skipped") or sweep.get("error")):
                results["steps"].append({"whbar_sweep": sweep})
        except Exception as exc:
            results["steps"].append({"whbar_sweep": {"error": str(exc)}})
        return results

    def swap(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience: prepara y envía un swap en un único método."""
        # Si no viene swap_quote.path, construirlo vía get_quote (token_in, token_out, amount, fee_bps, kind)
        swap_quote = params or {}
        try:
            needs_quote = isinstance(swap_quote, dict) and ("path" not in swap_quote)
            if needs_quote:
                kind = swap_quote.get("kind") or swap_quote.get("type") or "exact_in"
                token_in = swap_quote.get("token_in") or swap_quote.get("inputMint") or swap_quote.get("in")
                token_out = swap_quote.get("token_out") or swap_quote.get("outputMint") or swap_quote.get("out")
                amount = swap_quote.get("amount") or swap_quote.get("amount_in") or swap_quote.get("amountIn")
                fee_bps = swap_quote.get("fee_bps") or swap_quote.get("feeBps")
                if token_in and token_out and amount is not None and fee_bps is not None:
                    swap_quote = self.get_quote(str(token_in), str(token_out), int(amount), str(kind), int(fee_bps))
        except Exception:
            pass

        prep = self.swap_prepare(
            swap_quote,
            slippage_bps=int(params.get("slippage_bps", 50)) if isinstance(params, dict) else 50,
            deadline_s=int(params.get("deadline_s", 300)) if isinstance(params, dict) else 300,
            recipient_evm=params.get("recipient") if isinstance(params, dict) else None,
        )
        return self.swap_send(prep, wait=True)

    # ---------------- Allowance (ERC20.approve) ----------------
    def approve_prepare(self, token_in: str, amount: int, spender: Optional[str] = None, owner_evm: Optional[str] = None) -> Dict[str, Any]:
        """Prepara calldata para ERC20.approve(spender, amount) y estima gas.
        - token_in: HTS id o 0x... del ERC20 a aprobar
        - amount: cantidad a aprobar
        - spender: por defecto el swap_router
        - owner_evm: por defecto la address derivada de account_id
        """
        from eth_abi import encode as abi_encode  # type: ignore
        import eth_utils  # type: ignore

        token_evm = self._hts_to_evm(token_in)
        if not token_evm.startswith("0x"):
            raise ValueError("token_in inválido")
        target_spender = self._hts_to_evm(spender or self.config.contracts.get("swap_router", ""))
        if not target_spender.startswith("0x"):
            raise ValueError("swap_router no configurado correctamente")
        owner = owner_evm or self._hts_to_evm(self.account_id)

        approve_sel = eth_utils.keccak(text="approve(address,uint256)")[:4]
        calldata = approve_sel + abi_encode(["address", "uint256"], [target_spender, int(amount)])

        tx = {"from": owner, "to": token_evm, "data": "0x" + calldata.hex()}
        gas_estimate: Optional[int] = None
        try:
            gas = self._call_rpc("eth_estimateGas", [tx, "latest"])
            gas_estimate = int(gas, 16) if isinstance(gas, str) else gas
        except Exception as exc:
            self.logger.warning("eth_estimateGas approve failed: %s", exc)

        return {"to": token_evm, "data": "0x" + calldata.hex(), "from": owner, "gasEstimate": gas_estimate}

    # ---------------- Asociación HTS (Mirror Node) ----------------
    def check_associated(self, token_id: str, account_id: Optional[str] = None) -> Dict[str, Any]:
        """Comprueba si el token HTS está asociado a la cuenta vía Mirror Node.
        Retorna {associated: bool, details: ...} sin lanzar excepciones.
        """
        import requests
        acct = account_id or self.account_id
        base = f"https://mainnet.mirrornode.hedera.com/api/v1/accounts/{acct}/tokens?token.id={token_id}"
        try:
            r = requests.get(base, timeout=15)
            r.raise_for_status()
            data = r.json()
            tokens = data.get("tokens", [])
            associated = any(t.get("token_id") == token_id for t in tokens)
            return {"associated": associated, "details": tokens}
        except Exception as exc:
            return {"associated": False, "error": str(exc)}

    def check_contract_associated(self, token_id: str, contract_id: str) -> Dict[str, Any]:
        """Comprueba si un contrato (0.0.x) está asociado a un token HTS en Mirror Node."""
        import requests
        base = f"https://mainnet.mirrornode.hedera.com/api/v1/accounts/{contract_id}/tokens?token.id={token_id}"
        try:
            r = requests.get(base, timeout=15)
            r.raise_for_status()
            data = r.json()
            tokens = data.get("tokens", [])
            associated = any(t.get("token_id") == token_id for t in tokens)
            return {"associated": associated, "details": tokens}
        except Exception as exc:
            return {"associated": False, "error": str(exc)}

    # ---------------- Asociación HTS (Hedera SDK ejecución) ----------------
    def associate_execute(self, token_ids: Union[str, List[str]], account_id: Optional[str] = None, max_per_tx: int = 10) -> Dict[str, Any]:
        """Asocia tokens HTS a la cuenta usando Hedera SDK.
        - token_ids: str o lista de ids HTS ("0.0.x").
        - account_id: por defecto self.account_id.
        Retorna resumen con transacciones y estados.
        """
        try:
            from hedera import AccountId as HAccountId, PrivateKey as HPrivateKey, Client as HClient, TokenId as HTokenId
            from hedera import TokenAssociateTransaction
        except Exception as exc:  # ImportError u otros
            return {"executed": False, "error": f"Hedera SDK no disponible: {exc}"}

        acct = account_id or self.account_id
        # Cargar clave del archivo
        try:
            with open(os.path.expanduser(self.config.private_key_path), "r", encoding="utf-8") as f:
                key_json = json.load(f)
            priv_str = key_json.get("private_key") or key_json.get("operator_private_key") or key_json.get("privkey")
            if not priv_str:
                return {"executed": False, "error": "private_key no encontrado en private_key_path"}
        except Exception as exc:
            return {"executed": False, "error": f"error leyendo keyfile: {exc}"}

        # Cliente según red
        client = self._make_client()
        client = self._make_client()

        operator_id = HAccountId.fromString(acct)
        operator_key = self._load_hedera_private_key(priv_str)
        client.setOperator(operator_id, operator_key)

        # Normalizar tokens y filtrar ya asociados
        tokens_list = [token_ids] if isinstance(token_ids, str) else list(token_ids)
        to_assoc: List[str] = []
        for t in tokens_list:
            chk = self.check_associated(t, acct)
            if not chk.get("associated"):
                to_assoc.append(t)

        if not to_assoc:
            return {"executed": False, "reason": "ya asociados", "tokens": tokens_list}

        receipts: List[Dict[str, Any]] = []
        # Procesar en lotes
        for i in range(0, len(to_assoc), max_per_tx):
            batch = to_assoc[i:i + max_per_tx]
            try:
                tx = TokenAssociateTransaction()
                tx.setAccountId(operator_id)
                tx.setTokenIds([HTokenId.fromString(t) for t in batch])
                tx.freezeWith(client)
                tx_signed = tx.sign(operator_key)
                resp = tx_signed.execute(client)
                rec = resp.getReceipt(client)
                result = {"batch": batch, "status": str(rec.status)}
                receipts.append(result)
                if self.logger.isEnabledFor(logging.INFO):
                    self.logger.info("associate_execute: %s", result)
            except Exception as exc:
                err = {"batch": batch, "error": str(exc)}
                receipts.append(err)
                if self.logger.isEnabledFor(logging.WARNING):
                    self.logger.warning("associate_execute failed: %s", err)

        return {"executed": True, "account_id": acct, "receipts": receipts}

    def associate_contract_execute(self, token_ids: Union[str, List[str]], contract_id: str, max_per_tx: int = 10) -> Dict[str, Any]:
        """Intenta asociar tokens HTS a un contrato (0.0.x) usando Hedera SDK.
        Si el SDK/red no soportan asociar contratos, devuelve executed=False y no bloquea.
        """
        try:
            from hedera import Client as HClient, TokenId as HTokenId, ContractId as HContractId
            from hedera import PrivateKey as HPrivateKey
            from hedera import TokenAssociateTransaction
        except Exception as exc:
            return {"executed": False, "error": f"Hedera SDK no disponible: {exc}"}

        # Cliente y operador
        try:
            client = self._make_client()
            with open(os.path.expanduser(self.config.private_key_path), "r", encoding="utf-8") as f:
                key_json = json.load(f)
            priv_str = key_json.get("private_key") or key_json.get("operator_private_key") or key_json.get("privkey")
            operator_key = self._load_hedera_private_key(priv_str)
        except Exception as exc:
            return {"executed": False, "error": f"cliente/clave Hedera no disponible: {exc}"}

        try:
            c_id = HContractId.fromString(contract_id)
        except Exception as exc:
            return {"executed": False, "error": f"contract_id inválido: {exc}"}

        tokens_list = [token_ids] if isinstance(token_ids, str) else list(token_ids)
        to_assoc: List[str] = []
        for t in tokens_list:
            if isinstance(t, str) and t.count(".") == 2:
                chk = self.check_contract_associated(t, contract_id)
                if not chk.get("associated"):
                    to_assoc.append(t)

        if not to_assoc:
            return {"executed": False, "reason": "contrato ya asociado", "tokens": tokens_list}

        receipts: List[Dict[str, Any]] = []
        for i in range(0, len(to_assoc), max_per_tx):
            batch = to_assoc[i:i + max_per_tx]
            try:
                tx = TokenAssociateTransaction()
                # Algunos SDKs admiten setContractId; si no, esto lanzará excepción
                try:
                    tx.setContractId(c_id)  # type: ignore[attr-defined]
                except Exception as exc_set:
                    receipts.append({"batch": batch, "error": f"setContractId no soportado: {exc_set}"})
                    continue
                tx.setTokenIds([HTokenId.fromString(t) for t in batch])
                tx.freezeWith(client)
                tx_signed = tx.sign(operator_key)
                resp = tx_signed.execute(client)
                rec = resp.getReceipt(client)
                receipts.append({"batch": batch, "status": str(rec.status)})
            except Exception as exc:
                receipts.append({"batch": batch, "error": str(exc)})

        return {"executed": True, "contract_id": contract_id, "receipts": receipts}

    # ---------------- HTS Approve (Hedera SDK ejecución) ----------------
    def approve_hts_execute(self, token_id: str, spender_contract_id: str, amount: int = (1 << 63) - 1, account_id: Optional[str] = None) -> Dict[str, Any]:
        """Aprueba vía Hedera SDK (AccountAllowanceApproveTransaction) un allowance HTS al spender.
        Por defecto usa amount alto (signed long max) suficiente para whbar helper.
        """
        try:
            from hedera import AccountId as HAccountId, PrivateKey as HPrivateKey, Client as HClient
            from hedera import TokenId as HTokenId, AccountAllowanceApproveTransaction
        except Exception as exc:
            return {"executed": False, "error": f"Hedera SDK no disponible: {exc}"}

        acct = account_id or self.account_id
        # Cargar clave del archivo
        try:
            with open(os.path.expanduser(self.config.private_key_path), "r", encoding="utf-8") as f:
                key_json = json.load(f)
            priv_str = key_json.get("private_key") or key_json.get("operator_private_key") or key_json.get("privkey")
            if not priv_str:
                return {"executed": False, "error": "private_key no encontrado en private_key_path"}
        except Exception as exc:
            return {"executed": False, "error": f"error leyendo keyfile: {exc}"}

        client = self._make_client()

        operator_id = HAccountId.fromString(acct)
        operator_key = self._load_hedera_private_key(priv_str)
        client.setOperator(operator_id, operator_key)

        try:
            tx = AccountAllowanceApproveTransaction()
            tx.approveTokenAllowance(
                HTokenId.fromString(token_id),
                operator_id,  # owner (tu cuenta)
                HAccountId.fromString(spender_contract_id),  # spender (WhbarHelper)
                int(amount),
            )
            tx.freezeWith(client)
            resp = tx.sign(operator_key).execute(client)
            rec = resp.getReceipt(client)
            out = {"executed": True, "status": str(rec.status)}
            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info("approve_hts_execute: token=%s spender=%s amount=%s status=%s", token_id, spender_contract_id, amount, out["status"]) 
            return out
        except Exception as exc:
            err = {"executed": False, "error": str(exc)}
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning("approve_hts_execute failed: %s", err)
            return err

    def approve_hts_nft_execute(self, token_id: str, serial: int, spender_contract_id: str, account_id: Optional[str] = None) -> Dict[str, Any]:
        """Aprueba vía Hedera SDK una allowance específica de NFT (serial) al spender.
        Usa AccountAllowanceApproveTransaction.approveNftAllowance.
        """
        try:
            from hedera import AccountId as HAccountId, Client as HClient
            from hedera import PrivateKey as HPrivateKey
            from hedera import TokenId as HTokenId, NftId as HNftId, AccountAllowanceApproveTransaction
        except Exception as exc:
            return {"executed": False, "error": f"Hedera SDK no disponible: {exc}"}

        acct = account_id or self.account_id
        try:
            with open(os.path.expanduser(self.config.private_key_path), "r", encoding="utf-8") as f:
                key_json = json.load(f)
            priv_str = key_json.get("private_key") or key_json.get("operator_private_key") or key_json.get("privkey")
            if not priv_str:
                return {"executed": False, "error": "private_key no encontrado en private_key_path"}
        except Exception as exc:
            return {"executed": False, "error": f"error leyendo keyfile: {exc}"}

        client = self._make_client()
        operator_id = HAccountId.fromString(acct)
        operator_key = self._load_hedera_private_key(priv_str)
        client.setOperator(operator_id, operator_key)

        try:
            tx = AccountAllowanceApproveTransaction()
            token_obj = HTokenId.fromString(token_id)
            spender_id = HAccountId.fromString(spender_contract_id)
            used = None
            # Según tu SDK: approveTokenNftAllowance(NftId, owner, spender) ó (NftId, owner, spender, delegatingSpender)
            nft_id = HNftId(token_obj, int(serial))
            tx.approveTokenNftAllowance(nft_id, operator_id, spender_id)
            tx.freezeWith(client)
            resp = tx.sign(operator_key).execute(client)
            rec = resp.getReceipt(client)
            out = {"executed": True, "status": str(rec.status), "method": used}
            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info("approve_hts_nft_execute: token=%s serial=%s spender=%s status=%s via %s", token_id, serial, spender_contract_id, out["status"], used) 
            return out
        except Exception as exc:
            err = {"executed": False, "error": str(exc)}
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning("approve_hts_nft_execute failed: %s", err)
            return err

    # ---------------- Allowance check (read-only) ----------------
    def allowance_check(self, token_in: str, owner_evm: Optional[str] = None, spender: Optional[str] = None) -> Dict[str, Any]:
        """Consulta allowance ERC20.allowance(owner, spender) vía eth_call.
        Retorna {allowance: int}.
        """
        from eth_abi import encode as abi_encode  # type: ignore
        from eth_abi import decode as abi_decode  # type: ignore
        import eth_utils  # type: ignore

        token_evm = self._hts_to_evm(token_in)
        if not token_evm.startswith("0x"):
            raise ValueError("token_in inválido")
        owner = owner_evm or self._hts_to_evm(self.account_id)
        target_spender = self._hts_to_evm(spender or self.config.contracts.get("swap_router", ""))
        if not target_spender.startswith("0x"):
            raise ValueError("swap_router no configurado correctamente")

        sel = eth_utils.keccak(text="allowance(address,address)")[:4]
        calldata = sel + abi_encode(["address", "address"], [owner, target_spender])
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("allowance_check: token=%s owner=%s spender=%s", token_in, owner, target_spender)
        res = self._call_rpc("eth_call", [{"to": token_evm, "data": "0x" + calldata.hex()}, "latest"])
        value = abi_decode(["uint256"], bytes.fromhex(res[2:]))[0]
        out = {"allowance": int(value)}
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("allowance_check: out=%s", out)
        return out

    # ---------------- Asociación HTS (precompile prepare) ----------------
    def associate_prepare(self, token_ids: Union[str, List[str]], account_id: Optional[str] = None) -> Dict[str, Any]:
        """Prepara calldata para asociar tokens HTS usando el precompile HTS (0x...0167).
        Acepta un token (str) o una lista. Devuelve {to, data, from, gasEstimate, tokens}.
        """
        from eth_abi import encode as abi_encode  # type: ignore
        import eth_utils  # type: ignore

        acct = account_id or self.account_id
        owner = self._hts_to_evm(acct)
        if isinstance(token_ids, str):
            tokens = [token_ids]
        else:
            tokens = list(token_ids)
        tokens_evm = [self._hts_to_evm(t) for t in tokens]

        # HTS precompile address
        precompile = "0x" + (0).to_bytes(19, "big").hex() + (0x167).to_bytes(1, "big").hex()

        if len(tokens_evm) == 1:
            # associateToken(address account, address token)
            sel = eth_utils.keccak(text="associateToken(address,address)")[:4]
            calldata = sel + abi_encode(["address", "address"], [owner, tokens_evm[0]])
        else:
            # associateTokens(address account, address[] tokens)
            sel = eth_utils.keccak(text="associateTokens(address,address[])")[:4]
            calldata = sel + abi_encode(["address", "address[]"], [owner, tokens_evm])

        tx = {"from": owner, "to": precompile, "data": "0x" + calldata.hex()}
        gas_estimate: Optional[int] = None
        try:
            gas = self._call_rpc("eth_estimateGas", [tx, "latest"])
            gas_estimate = int(gas, 16) if isinstance(gas, str) else gas
        except Exception as exc:
            self.logger.warning("eth_estimateGas associate failed: %s", exc)

        return {"to": precompile, "data": "0x" + calldata.hex(), "from": owner, "gasEstimate": gas_estimate, "tokens": tokens_evm}

    def positions_status(self, pool_id: Optional[Union[int, str]] = None, positions: Optional[List[Union[int, str]]] = None) -> Dict[str, Any]:
        """Interfaz estándar: si 'positions' se pasa, devuelve estado por cada serial; si no, lista todas y filtra por pool.
        """
        try:
            all_positions = self._saucerswap_positions(self.account_id)
        except Exception as exc:
            return {"ok": False, "error": f"saucerswap api failed: {exc}"}
        if positions:
            out: List[Dict[str, Any]] = []
            for s in positions:
                try:
                    out.append(self.position_belongs_to_pool(s, pool_id))
                except Exception as exc:
                    out.append({"ok": False, "error": str(exc)})
            return {"ok": True, "positions": out}
        # sin lista: mapear todas las posiciones del owner al formato unificado
        out_all: List[Dict[str, Any]] = []
        for pos in all_positions:
            try:
                serial = int(pos.get("tokenSN"))
            except Exception:
                continue
            try:
                out_all.append(self.position_belongs_to_pool(serial, pool_id))
            except Exception:
                continue
        return {"ok": True, "positions": out_all}


__all__ = ["SaucerSwapAdapter", "SaucerSwapConfig"]
