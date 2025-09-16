import os
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
from dotenv import load_dotenv
import yaml


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
        root_env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", ".env")
        load_dotenv(dotenv_path=os.path.abspath(root_env))
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, log_level_str, logging.INFO)
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
        self.logger = logging.getLogger(self.__class__.__name__)

        self.api_key = os.getenv("SAUCER_API")
        if not self.api_key:
            raise RuntimeError("SAUCER_API no configurada en .env")

        config_path_abs = os.path.abspath(config_path)
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

        # Resolver rutas ABI desde YAML si están presentes
        try:
            abi_cfg = self.config.abi_files or {}
            self._router_abi_path = self._resolve_path_from_project_root(abi_cfg.get("swap_router"))
            self._quoter_abi_path = self._resolve_path_from_project_root(abi_cfg.get("quoter_v2"))
            self._whbar_helper_abi_path = self._resolve_path_from_project_root(abi_cfg.get("whbar_helper"))
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
        # .../LiquidityProvider/SaucerSwap/adapter -> go up 3 = LiquidityProvider
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
                    last_err = RuntimeError(f"HTTP {r.status_code}: {http_exc} body={body}")
                    raise last_err
                data = r.json()
                if "error" in data:
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
        return {
            ("amountOut" if kind == "exact_in" else "amountIn"): int(decoded[0]),
            "sqrtPriceX96AfterList": [int(x) for x in decoded[1]],
            "initializedTicksCrossedList": [int(x) for x in decoded[2]],
            "gasEstimate": int(decoded[3]),
            "path": "0x" + (path.hex() if kind == "exact_in" else path_rev.hex()),
        }

    # ---------------- Swap (preparación) ----------------
    def swap_prepare(self, token_in: str, token_out: str, amount: int, kind: str, fee_bps: int, slippage_bps: int = 50, deadline_s: int = 300, route_hops: Optional[List[Tuple[str,int]]] = None, recipient_evm: Optional[str] = None) -> Dict[str, Any]:
        from eth_abi import encode as abi_encode  # type: ignore
        import eth_utils  # type: ignore
        import time

        quote = self.get_quote(token_in, token_out, amount, kind, fee_bps, route_hops)
        amount_out = quote.get("amountOut")
        amount_in = quote.get("amountIn")
        path_hex = quote["path"]

        whbar = self.config.contracts.get("whbar")
        is_hbar_in = token_in.upper() == "HBAR"
        is_hbar_out = token_out.upper() == "HBAR"

        sender = recipient_evm or self.evm_address
        recipient = recipient_evm or sender
        router = self._hts_to_evm(self.config.contracts.get("swap_router", ""))
        if not router.startswith("0x"):
            raise ValueError("swap_router no configurado correctamente")

        if kind == "exact_in":
            min_out = (int(amount_out) * (10000 - slippage_bps)) // 10000
        else:
            max_in = (int(amount_in) * (10000 + slippage_bps)) // 10000

        value = 0
        tx_data = None

        # Auto-asociación HTS si token_out no está asociado (cuando no es HBAR)
        association: Optional[Dict[str, Any]] = None
        associated: Optional[bool] = None
        notes: List[str] = []
        if not is_hbar_out:
            # Consideramos que el usuario pasa token_out en formato HTS 0.0.x para poder consultar asociación
            if isinstance(token_out, str) and token_out.count(".") == 2:
                try:
                    chk = self.check_associated(token_out)
                    associated = bool(chk.get("associated"))
                    if not chk.get("associated"):
                        assoc_res = self.associate_execute(token_out)
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
                needed = max_in if kind == "exact_out" else amount
                alw = self.allowance_check(token_in)
                current = int(alw.get("allowance", 0))
                allowance_current = current
                allowance_needed = int(needed)
                if current < int(needed):
                    # MAX_UINT256
                    max_uint = (1 << 256) - 1
                    approve_tx = self.approve_prepare(token_in, max_uint)
                    notes.append("approve(MAX_UINT256) preparado por allowance insuficiente")
            except Exception as exc:
                notes.append(f"auto-approve error: {exc}")

        # Deadline absoluto (epoch seconds)
        deadline_ts = int(time.time()) + int(os.environ.get("SWAP_DEADLINE_S", str(deadline_s)))

        if kind == "exact_in":
            # exactInput((bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum))
            exact_sel = eth_utils.keccak(text="exactInput((bytes,address,uint256,uint256,uint256))")[:4]
            args_tuple = (
                bytes.fromhex(path_hex[2:]),
                recipient,
                int(deadline_ts),
                int(amount),
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
                value = int(amount) * (10 ** 10)
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
                int(amount),
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

        gas_estimate: Optional[int] = None
        try:
            gas = self._call_rpc("eth_estimateGas", [tx, "latest"])
            gas_estimate = int(gas, 16) if isinstance(gas, str) else gas
        except Exception as exc:
            notes.append("eth_estimateGas revert: verificar asociación HTS del token_out, allowance si aplica y uso de multicall para HBAR")
            self.logger.warning("eth_estimateGas failed: %s", exc)

        return {
            "to": router,
            "data": "0x" + tx_data.hex(),
            "value": value,
            "gasEstimate": gas_estimate,
            "quote": quote,
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

        # Si falta gas, intenta estimar
        if "gas" not in tx_to_sign:
            try:
                est = self._call_rpc("eth_estimateGas", [{"from": address_from, "to": tx["to"], "data": tx_to_sign["data"], "value": hex(tx_to_sign.get("value", 0)) if tx_to_sign.get("value") else "0x0"}, "latest"])
                tx_to_sign["gas"] = int(est, 16) if isinstance(est, str) else est
            except Exception:
                tx_to_sign["gas"] = 300000

        # Firmar y enviar
        acct = Account.from_key(bytes.fromhex(self._private_key_hex))
        signed = acct.sign_transaction(tx_to_sign)
        raw_hex = signed.rawTransaction.hex()
        payload = raw_hex if isinstance(raw_hex, str) and raw_hex.startswith("0x") else ("0x" + raw_hex)
        tx_hash = self._call_rpc("eth_sendRawTransaction", [payload])
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
                        receipt = rec
                        break
                except Exception:
                    pass
                time.sleep(poll_s)
            out["receipt"] = receipt
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
        # 3) Barrido WHBAR si quedara en el usuario (post-swap residual)
        try:
            owner = prep.get("from") or self.evm_address
            sweep = self._whbar_sweep_unwrap(owner)
            if sweep and (sweep.get("executed") or sweep.get("skipped")):
                results["steps"].append({"whbar_sweep": sweep})
        except Exception as exc:
            results["steps"].append({"whbar_sweep": {"error": str(exc)}})
        return results

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
                receipts.append({"batch": batch, "status": str(rec.status)})
            except Exception as exc:
                receipts.append({"batch": batch, "error": str(exc)})

        return {"executed": True, "account_id": acct, "receipts": receipts}

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
            return {"executed": True, "status": str(rec.status)}
        except Exception as exc:
            return {"executed": False, "error": str(exc)}

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
        res = self._call_rpc("eth_call", [{"to": token_evm, "data": "0x" + calldata.hex()}, "latest"])
        value = abi_decode(["uint256"], bytes.fromhex(res[2:]))[0]
        return {"allowance": int(value)}

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


__all__ = ["SaucerSwapAdapter", "SaucerSwapConfig"]
