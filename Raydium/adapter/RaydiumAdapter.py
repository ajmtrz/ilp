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
        )

        if not self.config.cluster:
            raise ValueError("solana.cluster is required")
        if not self.config.rpc_endpoints:
            raise ValueError("solana.rpc_endpoints must contain at least one endpoint")
        if not self.config.program_id_clmm:
            raise ValueError("raydium.program_id_clmm is required")

        self.rpc = EndpointRotator(self.config.rpc_endpoints)
        self.logger.info("RaydiumAdapter inicializado (cluster=%s, endpoints=%d)", self.config.cluster, len(self.config.rpc_endpoints))

        idl = ClmmDecoder.fetch_idl_onchain(
            program_id=self.config.program_id_clmm,
            cluster=self.config.cluster,
            wallet_path=self.config.keypair_path,
        )
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
        data = self._rpc_call_with_failover("getAccountInfo", [pubkey, {"encoding": "base64"}])
        result = data.get("result") or {}
        value = result.get("value") if isinstance(result, dict) else None
        if not value:
            return None
        arr = value.get("data", [None, None]) if isinstance(value, dict) else [None, None]
        return arr[0]

    def _check_position_exists(self, position_nft_mint: str, pool_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        import base64  # type: ignore

        acc_name, _, _ = self.decoder.infer_position_offsets()
        pda, _bump = self._derive_personal_position_pda(position_nft_mint)
        b64 = self._get_account_info_base64(pda)
        if not b64:
            return False, None
        raw = base64.b64decode(b64)
        details = self.decoder.anchor_cli_decode(
            program_id=self.config.program_id_clmm,
            account_type=acc_name,
            account_pubkey=pda,
            cluster=self.config.cluster,
            wallet_path=self.config.keypair_path,
        )
        return True, details

    def check_position_exists_tool(self, position_nft_mint: str, pool_address: Optional[str] = None) -> Dict[str, Any]:
        if not position_nft_mint:
            return {"exists": False, "details": {"reason": "missing position_nft_mint"}}
        exists, details = self._check_position_exists(position_nft_mint=position_nft_mint, pool_address=pool_address)
        if exists:
            return {"exists": True, "details": details or {}}
        return {"exists": False, "details": {}}


__all__ = ["RaydiumAdapter", "RaydiumConfig"]


