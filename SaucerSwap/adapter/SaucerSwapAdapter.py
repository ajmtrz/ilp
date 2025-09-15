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
    def _get_router_abi_path(self) -> str:
        # LiquidityProvider/SaucerSwap/config/SwapRouter.json
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "config", "SwapRouter.json")

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
        # Custom errors
        self._ensure_router_abi_loaded()
        idx = self._router_error_index or {}
        if selector in idx:
            err = idx[selector]
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
        whbar = self.config.contracts.get("whbar")
        def norm(t: str) -> str:
            if t.upper() == "HBAR":
                if not whbar:
                    raise ValueError("whbar no configurado")
                return self._hts_to_evm(whbar)
            return self._hts_to_evm(t)

        tokens = [norm(token_in)] + [norm(t) for (t, _f) in route_hops] + [norm(token_out)]
        fees = [fee_bps] + [f for (_t, f) in route_hops]
        path = self._encode_path_v2(tokens, fees)

        quoter = self._hts_to_evm(self.config.contracts.get("quoter_v2", ""))
        if not quoter.startswith("0x"):
            raise ValueError("quoter_v2 no configurado correctamente")

        if kind == "exact_in":
            selector = eth_utils.keccak(text="quoteExactInput(bytes,uint256)")[:4]
            calldata = selector + abi_encode(["bytes", "uint256"], [path, amount])
        elif kind == "exact_out":
            selector = eth_utils.keccak(text="quoteExactOutput(bytes,uint256)")[:4]
            tokens_rev = list(reversed(tokens))
            fees_rev = list(reversed(fees))
            path_rev = self._encode_path_v2(tokens_rev, fees_rev)
            calldata = selector + abi_encode(["bytes", "uint256"], [path_rev, amount])
        else:
            raise ValueError("kind debe ser 'exact_in' o 'exact_out'")

        result = self._call_rpc("eth_call", [{"to": quoter, "data": "0x" + calldata.hex()}, "latest"])
        decoded = abi_decode(["uint256", "uint160[]", "uint32[]", "uint256"], bytes.fromhex(result[2:]))
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
        net = (self.config.network or "mainnet").lower()
        if net == "testnet":
            client = HClient.for_testnet()
        elif net == "previewnet":
            client = HClient.for_previewnet()
        else:
            client = HClient.for_mainnet()

        operator_id = HAccountId.fromString(acct)
        operator_key = HPrivateKey.fromString(priv_str)
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
