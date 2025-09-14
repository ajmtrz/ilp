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


class EndpointRotator:
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

        sol = cfg["solana"]
        ray = cfg["raydium"]

        self.config = RaydiumConfig(
            cluster=sol["cluster"],
            rpc_endpoints=sol["rpc_endpoints"],
            wss_endpoints=sol.get("wss_endpoints", []),
            keypair_path=sol["keypair_path"],
            program_id_clmm=ray["program_id_clmm"],
        )

        self.rpc = EndpointRotator(self.config.rpc_endpoints)
        self.logger.info("RaydiumAdapter inicializado (cluster=%s, endpoints=%d)", self.config.cluster, len(self.config.rpc_endpoints))

        try:
            idl = ClmmDecoder.fetch_idl_onchain(
                program_id=self.config.program_id_clmm,
                cluster=self.config.cluster,
                wallet_path=self.config.keypair_path,
            )
            self.logger.debug("IDL obtenido on-chain para %s", self.config.program_id_clmm)
        except Exception as exc:
            self.logger.warning("Fallo al obtener IDL on-chain (%s). Usando fallback local.", exc)
            config_dir = os.path.dirname(config_path_abs)
            local_idl_path = os.path.join(config_dir, f"{self.config.program_id_clmm}-idl.json")
            with open(local_idl_path, "r", encoding="utf-8") as f:
                idl = json.load(f)

        self.decoder = ClmmDecoder(idl)
        self.owner_pubkey = self._derive_owner_from_keypair(self.config.keypair_path)

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
        raise RuntimeError("All RPC endpoints failed") from last_error

    def _owner_holds_nft_mint(self, owner_pubkey: str, mint_pubkey: str) -> bool:
        data = self._rpc_call_with_failover("getTokenAccountsByOwner", [owner_pubkey, {"mint": mint_pubkey}, {"encoding": "jsonParsed"}])
        value = (data.get("result", {}) or {}).get("value", [])
        for entry in value:
            amount = entry["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"]
            if int(amount) > 0:
                return True
        return False

    def _check_position_exists(self, position_nft_mint: str, pool_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        acc_name, pool_offset, nft_mint_offset = self.decoder.infer_position_offsets()

        filters = [{"memcmp": {"offset": nft_mint_offset, "bytes": position_nft_mint}}]
        if pool_address:
            filters.append({"memcmp": {"offset": pool_offset, "bytes": pool_address}})
        data = self._rpc_call_with_failover("getProgramAccounts", [self.config.program_id_clmm, {"encoding": "base64", "filters": filters, "commitment": "confirmed"}])
        result = data.get("result", []) or []
        if not result:
            return False, None

        import base64  # type: ignore
        import base58  # type: ignore

        for acc in result:
            b64 = (acc.get("account", {}).get("data", [None, None]) or [None, None])[0]
            if not b64:
                continue
            raw = base64.b64decode(b64)
            if not self._owner_holds_nft_mint(self.owner_pubkey, position_nft_mint):
                continue
            if not pool_address and len(raw) >= pool_offset + 32:
                pool_address = base58.b58encode(raw[pool_offset:pool_offset + 32]).decode("utf-8")
            account_pubkey = acc.get("pubkey")
            if not isinstance(account_pubkey, str):
                continue
            details = self.decoder.anchor_cli_decode(
                program_id=self.config.program_id_clmm,
                account_type=acc_name,
                account_pubkey=account_pubkey,
                cluster=self.config.cluster,
                wallet_path=self.config.keypair_path,
            )
            return True, details
        return False, None

    def check_position_exists_tool(self, position_nft_mint: str, pool_address: Optional[str] = None) -> Dict[str, Any]:
        if not position_nft_mint:
            return {"exists": False, "details": {"reason": "missing position_nft_mint"}}
        exists, details = self._check_position_exists(position_nft_mint=position_nft_mint, pool_address=pool_address)
        if exists:
            return {"exists": True, "details": details or {}}
        return {"exists": False, "details": {}}


__all__ = ["RaydiumAdapter", "RaydiumConfig"]


