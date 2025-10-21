from __future__ import annotations

from typing import Dict, Any

from .Raydium.adapter.RaydiumAdapter import RaydiumAdapter  # type: ignore
from .SaucerSwap.adapter.SaucerSwapAdapter import SaucerSwapAdapter  # type: ignore


class AdapterFactory:
    def __init__(self, project_root: str) -> None:
        self.project_root = project_root

    def get(self, protocol: str) -> Any:
        p = (protocol or "").lower()
        if p == "raydium":
            return RaydiumAdapter(config_path=f"{self.project_root}/adapters/Raydium/config/solana.raydium.yaml")
        if p == "saucerswap":
            # Hedera config file path
            return SaucerSwapAdapter(config_path=f"{self.project_root}/adapters/SaucerSwap/config/hedera.saucerswap.yaml")
        raise ValueError(f"Protocolo no soportado: {protocol}")
