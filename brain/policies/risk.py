from __future__ import annotations

from typing import Dict, Any, Optional, Tuple
import time

class RateLimiter:
    """Rate limit simple por clave (p. ej., protocolo o pool). Ventana deslizante por minuto.
    Si no se configura un máximo, no limita.
    """

    def __init__(self) -> None:
        self._buckets: Dict[str, Tuple[int, float]] = {}

    def allow(self, key: str, max_per_minute: Optional[int]) -> bool:
        if not max_per_minute or max_per_minute <= 0:
            return True
        now = time.time()
        count, start = self._buckets.get(key, (0, now))
        if now - start >= 60.0:
            self._buckets[key] = (1, now)
            return True
        if count + 1 > max_per_minute:
            return False
        self._buckets[key] = (count + 1, start)
        return True


class RiskManager:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config or {}
        self.rl = RateLimiter()

    def _check_slippage(self, proposal: Dict[str, Any]) -> None:
        limits = (self.config or {}).get("limits") or {}
        slippage_max = limits.get("slippage_bps_max")
        if slippage_max is None:
            return
        slippage_max = int(slippage_max)
        if int(proposal.get("slippage_bps", 0)) > slippage_max:
            raise ValueError(f"slippage_bps excede máximo permitido ({slippage_max})")

    def _check_exposure(self, proposal: Dict[str, Any]) -> None:
        protocol = (proposal.get("protocol") or "").lower()
        pool_id = proposal.get("pool_id")
        exposure = proposal.get("exposure")
        if protocol and pool_id and exposure is not None:
            prot = ((self.config or {}).get("protocols") or {}).get(protocol) or {}
            pools = prot.get("pools") or {}
            pool_cfg = pools.get(pool_id) or {}
            exp_max = pool_cfg.get("exposure_max")
            if exp_max is None:
                raise ValueError("exposure_max no configurado para pool; config explícita requerida")
            if int(exposure) > int(exp_max):
                raise ValueError(f"exposure {exposure} > exposure_max {exp_max} para pool {pool_id}")

    def _check_frequency(self, intent: str, proposal: Dict[str, Any]) -> None:
        protocol = (proposal.get("protocol") or "").lower()
        limits = (self.config or {}).get("limits") or {}
        per_min = limits.get("max_actions_per_minute")
        key = f"{intent}:{protocol}" if protocol else intent
        if not self.rl.allow(key, int(per_min) if per_min is not None else None):
            raise ValueError("rate limit excedido: max_actions_per_minute")

    def validate(self, intent: str, proposal: Dict[str, Any]) -> None:
        self._check_slippage(proposal)
        self._check_exposure(proposal)
        self._check_frequency(intent, proposal)


def enforce_limits(config: Dict[str, Any], proposal: Dict[str, Any]) -> None:
    # Compat retro: valida sólo slippage si se usa la función antigua
    RiskManager(config)._check_slippage(proposal)


