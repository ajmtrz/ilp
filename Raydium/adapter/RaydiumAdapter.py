import os
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv
import yaml

from .ClmmDecoder import ClmmDecoder


@dataclass
class RaydiumConfig:
    cluster: str
    rpc_endpoints: List[str]
    wss_endpoints: List[str]
    keypair_path: str
    program_id_clmm: str
    api_base: str
    priority_fee_tier: str


class EndpointRotator:
    """Simple failover: iterate endpoints on failure without retrying the same one."""

    def __init__(self, endpoints: List[str]):
        if not endpoints:
            raise ValueError("At least one RPC endpoint is required")
        self._endpoints = endpoints
        self._index = 0

    @property
    def current(self) -> str:
        return self._endpoints[self._index]

    def rotate(self) -> str:
        self._index = (self._index + 1) % len(self._endpoints)
        return self.current


class RaydiumAdapter:
    def __init__(self, config_path: str):
        root_env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", ".env")
        load_dotenv(dotenv_path=os.path.abspath(root_env))
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, log_level_str, logging.INFO)
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
        self.logger = logging.getLogger(self.__class__.__name__)

        config_path_abs = os.path.abspath(config_path)
        with open(config_path_abs, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        try:
            sol = cfg["solana"]
            ray = cfg["raydium"]
        except Exception as exc:
            raise ValueError("Invalid configuration structure. Expected keys: solana, raydium") from exc

        self.config = RaydiumConfig(
            cluster=sol.get("cluster"),
            rpc_endpoints=sol.get("rpc_endpoints", []),
            wss_endpoints=sol.get("wss_endpoints", []),
            keypair_path=sol.get("keypair_path"),
            program_id_clmm=ray.get("program_id_clmm"),
            api_base=ray.get("api_base", "https://transaction-v1.raydium.io"),
            priority_fee_tier=str(ray.get("priority_fee_tier", "h")).lower(),
        )

        if not self.config.cluster:
            raise ValueError("solana.cluster is required")
        if not self.config.rpc_endpoints:
            raise ValueError("solana.rpc_endpoints must contain at least one endpoint")
        if not self.config.program_id_clmm:
            raise ValueError("raydium.program_id_clmm is required")
        if self.config.priority_fee_tier not in ("vh", "h", "m"):
            raise ValueError("raydium.priority_fee_tier must be one of: vh, h, m")

        self.rpc = EndpointRotator(self.config.rpc_endpoints)
        self.logger.info(
            "RaydiumAdapter inicializado (cluster=%s, rpc_endpoints=%d, api_base=%s, tx=v0, fee_tier=%s)",
            self.config.cluster,
            len(self.config.rpc_endpoints),
            self.config.api_base,
            self.config.priority_fee_tier,
        )

        idl = ClmmDecoder.fetch_idl_onchain(
            program_id=self.config.program_id_clmm,
            cluster=self.config.cluster,
            wallet_path=self.config.keypair_path,
        )
        self.decoder = ClmmDecoder(idl)

        self.owner_pubkey = self._derive_owner_from_keypair(self.config.keypair_path)
        self.SOL_MINT = "So11111111111111111111111111111111111111112"

    # ---------------- Raydium Trade API: Quote ----------------
    def get_quote(self, input_mint: str, output_mint: str, amount: int, kind: str, slippage_bps: int) -> Dict[str, Any]:
        if kind not in ("exact_in", "exact_out"):
            raise ValueError("kind debe ser 'exact_in' o 'exact_out'")
        if not input_mint or not output_mint:
            raise ValueError("input_mint y output_mint son obligatorios")
        if int(amount) <= 0:
            raise ValueError("amount debe ser > 0 (en unidades mínimas)")
        if not (0 < int(slippage_bps) <= 10_000):
            raise ValueError("slippage_bps fuera de rango (1..10000)")
        # Autodetectar wrap/unwrap según mints
        wrap_sol = (input_mint == self.SOL_MINT)
        unwrap_sol = (output_mint == self.SOL_MINT)
        path = "compute/swap-base-in" if kind == "exact_in" else "compute/swap-base-out"
        params = {
            "inputMint": input_mint,
            "outputMint": output_mint,
            "amount": str(int(amount)),
            "slippageBps": int(slippage_bps),
            "txVersion": "V0",
        }
        data = self._api_get(path, params=params)
        if isinstance(data, dict) and data.get("success") is False and data.get("message"):
            raise RuntimeError(f"Raydium compute error: {data.get('message')}")
        # La API devuelve un objeto complejo; encapsulamos lo esencial y guardamos swapResponse completo
        return {
            "swapResponse": data,
            "kind": kind,
            "inputMint": input_mint,
            "outputMint": output_mint,
            "amount": int(amount),
            "slippageBps": int(slippage_bps),
            "wrapSol": bool(wrap_sol),
            "unwrapSol": bool(unwrap_sol),
        }

    # ---------------- Raydium Trade API: Prepare ----------------
    def _derive_ata(self, owner_pubkey: str, mint: str) -> Optional[str]:
        """Deriva Associated Token Account (ATA) para (owner,mint)."""
        try:
            from solders.pubkey import Pubkey  # type: ignore
        except Exception as exc:
            self.logger.warning("solders no disponible para derivar ATA: %s", exc)
            return None
        try:
            TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            ATA_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
            owner_pk = Pubkey.from_string(owner_pubkey)
            mint_pk = Pubkey.from_string(mint)
            seeds = [bytes(owner_pk), bytes(TOKEN_PROGRAM_ID), bytes(mint_pk)]
            ata, _bump = Pubkey.find_program_address(seeds, ATA_PROGRAM_ID)
            return str(ata)
        except Exception as exc:
            self.logger.warning("Error derivando ATA: %s", exc)
            return None

    def swap_prepare(self, swap_quote: Dict[str, Any]) -> Dict[str, Any]:
        kind = swap_quote.get("kind")
        if kind not in ("exact_in", "exact_out"):
            raise ValueError("swap_quote.kind inválido")
        # Obtener prioridad
        priority = self._get_priority_fee_micro_lamports()
        if priority is None:
            # fallback conservador si la API no devuelve datos
            priority = {"vh": 1_000_000, "h": 500_000, "m": 200_000}.get(self.config.priority_fee_tier, 500_000)
        payload = {
            "computeUnitPriceMicroLamports": str(priority) if priority is not None else None,
            "swapResponse": swap_quote.get("swapResponse"),
            "txVersion": "V0",
            "wallet": self.owner_pubkey,
        }
        # wrap/unwrap SOL
        wrap_sol = bool(swap_quote.get("wrapSol"))
        unwrap_sol = bool(swap_quote.get("unwrapSol"))
        if wrap_sol:
            payload["wrapSol"] = True
        if unwrap_sol:
            payload["unwrapSol"] = True
        # input/output accounts
        input_mint = swap_quote.get("inputMint")
        output_mint = swap_quote.get("outputMint")
        if input_mint and input_mint != self.SOL_MINT:  # no SOL nativo
            ata_in = self._derive_ata(self.owner_pubkey, input_mint)
            if ata_in:
                payload["inputAccount"] = ata_in
        if output_mint and output_mint == self.SOL_MINT:
            # si se desea SOL nativo, la API soporta unwrapSol
            payload["unwrapSol"] = True

        path = "transaction/swap-base-in" if kind == "exact_in" else "transaction/swap-base-out"
        res = self._api_post(path, payload)
        if isinstance(res, dict) and res.get("success") is False and res.get("message"):
            raise RuntimeError(f"Raydium transaction error: {res.get('message')}")
        # Extraer transacciones de forma robusta (puede venir list o dict)
        transactions: List[str] = []
        items: List[Any] = []
        if isinstance(res, list):
            items = res
        elif isinstance(res, dict):
            data_field = res.get("data")
            if isinstance(data_field, list):
                items = data_field
            elif isinstance(data_field, dict):
                items = [data_field]
            else:
                # a veces la tx está directamente en res
                items = [res]
        for it in items:
            if isinstance(it, dict) and isinstance(it.get("transaction"), str):
                transactions.append(it["transaction"])
        if not transactions:
            raise RuntimeError("Raydium API no devolvió transacciones a firmar")
        return {
            "transactions": transactions,
            "txVersion": "V0",
        }

    # ---------------- Raydium Trade API: Send ----------------
    def _load_solana_keypair(self):
        try:
            from solders.keypair import Keypair  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Falta dependencia solders: {exc}")
        expanded_path = os.path.expanduser(self.config.keypair_path)
        with open(expanded_path, "r", encoding="utf-8") as f:
            key_data = json.load(f)
        secret = bytes(key_data)
        # Formato estándar Solana: 64 bytes (priv||pub)
        if len(secret) == 64:
            return Keypair.from_bytes(secret)
        # Si viniera 32 bytes, usar como seed
        seed = secret[:32]
        return Keypair.from_seed(seed)

    def _rpc_client(self):
        try:
            from solana.rpc.api import Client  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Falta dependencia solana-py: {exc}")
        return Client(self.rpc.current)

    def swap_send(self, prep: Dict[str, Any], wait: bool = True) -> Dict[str, Any]:
        try:
            from solana.rpc.api import Client  # type: ignore
            from solana.rpc.types import TxOpts  # type: ignore
            from solders.transaction import VersionedTransaction  # type: ignore
            from solders.signature import Signature as SolSig  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Faltan dependencias para V0: {exc}")

        kp = self._load_solana_keypair()
        client = self._rpc_client()
        signatures: List[str] = []
        receipts: List[Dict[str, Any]] = []
        def _extract_sig(resp_obj: Any) -> Optional[str]:
            if isinstance(resp_obj, dict):
                return resp_obj.get("result") or resp_obj.get("value") or resp_obj.get("signature")
            # RPCResponse-like
            val = getattr(resp_obj, "value", None)
            if isinstance(val, str):
                return val
            # Fallback to string
            try:
                s = str(resp_obj)
                if not s:
                    return None
                # Intenta extraer base58 de "Signature(<base58>)"
                import re
                m = re.search(r"Signature\(([1-9A-HJ-NP-Za-km-z]{32,})\)", s)
                if m:
                    return m.group(1)
                return s
            except Exception:
                return None
        def _to_jsonable(obj: Any) -> Any:
            if isinstance(obj, (str, int, float, bool)) or obj is None:
                return obj
            if isinstance(obj, dict):
                return {k: _to_jsonable(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_to_jsonable(x) for x in obj]
            val = getattr(obj, "value", None)
            if val is not None:
                return {"value": _to_jsonable(val)}
            to_dict = getattr(obj, "to_dict", None)
            if callable(to_dict):
                try:
                    return to_dict()
                except Exception:
                    pass
            try:
                return str(obj)
            except Exception:
                return None
        for tx_b64 in prep.get("transactions", []):
            raw = __import__("base64").b64decode(tx_b64)
            sig = None
            try:
                vtx = VersionedTransaction.from_bytes(raw)
                # Firmar la transacción con nuestro keypair
                msg = vtx.message
                signed_vtx = VersionedTransaction(msg, [kp])
                opts = TxOpts(skip_preflight=True, preflight_commitment="confirmed")
                resp = client.send_raw_transaction(bytes(signed_vtx), opts=opts)
                sig = _extract_sig(resp)
            except Exception as exc:
                self.logger.error("Error enviando transacción v0: %s", exc)
                receipts.append({"error": str(exc)})
                continue
            signatures.append(sig)
            if wait and sig:
                try:
                    sig_obj = SolSig.from_string(sig) if isinstance(sig, str) else sig
                    conf = client.confirm_transaction(sig_obj, commitment="confirmed")
                    receipts.append(_to_jsonable(conf))
                except Exception as exc:
                    receipts.append({"warn": f"confirm failed: {exc}"})
        return {"signatures": signatures, "receipts": receipts}
    # ---------------- HTTP helpers (Raydium Trade API) ----------------
    def _api_get(self, path: str, params: Optional[Dict[str, Any]] = None, timeout: int = 20) -> Dict[str, Any]:
        import requests
        url = self.config.api_base.rstrip("/") + "/" + path.lstrip("/")
        r = requests.get(url, params=params or {}, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"data": data}
        return data

    def _api_post(self, path: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        import requests
        url = self.config.api_base.rstrip("/") + "/" + path.lstrip("/")
        r = requests.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"data": data}
        return data

    # ---------------- Priority fee helper ----------------
    def _get_priority_fee_micro_lamports(self) -> Optional[int]:
        """Obtiene computeUnitPriceMicroLamports según tier (vh/h/m) usando la API si es posible.
        Si falla, devuelve None y el llamante puede omitir el campo.
        """
        try:
            # Endpoint esperado: /priority-fee
            data = self._api_get("priority-fee")
            tiers = (((data or {}).get("data") or {}).get("default") or {})
            val = tiers.get(self.config.priority_fee_tier)
            return int(val) if val is not None else None
        except Exception:
            return None

    def _derive_owner_from_keypair(self, keypair_path: str) -> str:
        import base58  # type: ignore
        from nacl.signing import SigningKey  # type: ignore

        expanded_path = os.path.expanduser(keypair_path)
        with open(expanded_path, "r", encoding="utf-8") as f:
            key_data = json.load(f)
        key_bytes = bytes(key_data)
        seed = key_bytes[:32] if len(key_bytes) == 64 else key_bytes
        sk = SigningKey(seed)
        vk = sk.verify_key
        return base58.b58encode(vk.encode()).decode("utf-8")

    def _rpc_call_with_failover(self, method: str, params: List[Any]) -> Dict[str, Any]:
        import requests

        last_error: Optional[Exception] = None
        for _ in range(len(self.config.rpc_endpoints)):
            url = self.rpc.current
            try:
                resp = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                if "error" in data:
                    raise RuntimeError(f"RPC error from {url}: {data['error']}")
                return data
            except Exception as exc:
                self.logger.warning("RPC endpoint failed (%s): %s", url, exc)
                last_error = exc
                self.rpc.rotate()
        self.logger.error("Todos los endpoints RPC fallaron")
        raise RuntimeError("All RPC endpoints failed") from last_error

    def _derive_personal_position_pda(self, nft_mint_b58: str) -> Tuple[str, int]:
        try:
            from solders.pubkey import Pubkey  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Falta dependencia 'solders'. Instala con: pip install solders") from exc
        program = Pubkey.from_string(self.config.program_id_clmm)
        mint_pk = Pubkey.from_string(nft_mint_b58)
        pda, bump = Pubkey.find_program_address([b"position", bytes(mint_pk)], program)
        return str(pda), bump

    def _get_account_info_base64(self, pubkey: str) -> Optional[str]:
        try:
            data = self._rpc_call_with_failover("getAccountInfo", [pubkey, {"encoding": "base64"}])
            result = data.get("result") or {}
            value = result.get("value") if isinstance(result, dict) else None
            if not value:
                self.logger.debug("Cuenta no encontrada: %s", pubkey)
                return None
            arr = value.get("data", [None, None]) if isinstance(value, dict) else [None, None]
            return arr[0]
        except Exception as exc:
            self.logger.error("Error obteniendo información de cuenta %s: %s", pubkey, exc)
            return None

    def _decode_account(self, account_type: str, pubkey: str, raw_b64: str) -> Dict[str, Any]:
        import base64  # type: ignore
        raw = base64.b64decode(raw_b64)
        return self.decoder.anchor_cli_decode(
            program_id=self.config.program_id_clmm,
            account_type=account_type,
            account_pubkey=pubkey,
            cluster=self.config.cluster,
            wallet_path=self.config.keypair_path,
        ) or {}

    def check_position_exists_tool(self, position_nft_mint: str, pool_address: Optional[str] = None) -> Dict[str, Any]:
        if not position_nft_mint:
            return {"exists": False, "details": {"reason": "missing position_nft_mint"}}
        try:
            # 1) Derivar PDA y leer posición
            acc_name, _, _ = self.decoder.infer_position_offsets()
            pda, _bump = self._derive_personal_position_pda(position_nft_mint)
            pos_b64 = self._get_account_info_base64(pda)
            if not pos_b64:
                return {"exists": False, "details": {}}
            pos_details = self._decode_account(acc_name, pda, pos_b64)
            if not isinstance(pos_details, dict):
                return {"exists": False, "details": {}}
            # 2) Leer pool y extraer tick actual
            pool_id = pos_details.get("pool_id")
            current_tick: Optional[int] = None
            if isinstance(pool_id, str) and pool_id:
                pool_b64 = self._get_account_info_base64(pool_id)
                if pool_b64:
                    pool_details = self._decode_account("PoolState", pool_id, pool_b64)
                    # Intentar diferentes nombres comunes
                    for key in ("tick_current_index", "tickCurrentIndex", "tick_current", "current_tick_index"):
                        if isinstance(pool_details, dict) and key in pool_details:
                            try:
                                current_tick = int(pool_details[key])
                                self.logger.info("Pool encontrada: ID=%s, tickCurrent=%s", pool_id, current_tick)
                                break
                            except Exception:
                                pass
                    if current_tick is None:
                        self.logger.warning("No se pudo extraer tickCurrent de la pool %s", pool_id)
                else:
                    self.logger.warning("Cuenta de pool no encontrada: %s", pool_id)
            else:
                self.logger.warning("pool_id inválido en posición: %s", pool_id)
            # 3) Unir y devolver
            merged = dict(pos_details)
            if current_tick is not None:
                merged["tick_current"] = current_tick
            return {"exists": True, "details": merged}
        except Exception as exc:
            self.logger.error("Error verificando posición %s: %s", position_nft_mint, exc)
            return {"exists": False, "details": {"error": f"position check failed: {exc}"}}


__all__ = ["RaydiumAdapter", "RaydiumConfig"]


