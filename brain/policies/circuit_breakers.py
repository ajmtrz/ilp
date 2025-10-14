from __future__ import annotations

from typing import Dict, Any, Tuple
import time


class CircuitBreakers:
    """Circuit breakers sencillos a nivel de orquestación.
    - consecutive_fail_limit: bloquea tras N fallos consecutivos durante window_s.
    - cooldown_s: tiempo de bloqueo tras activación.
    Notas: Umbrales de volatilidad/drawdown pueden añadirse cuando existan métricas runtime.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        cb = (config or {}).get("circuit_breakers") or {}
        self.consecutive_fail_limit = int(cb.get("consecutive_fail_limit", 3))
        self.window_s = int(cb.get("window_s", 120))
        self.cooldown_s = int(cb.get("cooldown_s", 60))
        self._fails: Tuple[int, float] = (0, 0.0)  # (count, window_start)
        self._blocked_until: float = 0.0

    def before_action(self) -> None:
        now = time.time()
        if now < self._blocked_until:
            raise RuntimeError("circuit breaker activo: cooldown en curso")

    def on_success(self) -> None:
        # Resetear ventana de fallos
        self._fails = (0, 0.0)

    def on_failure(self) -> None:
        now = time.time()
        count, start = self._fails
        if start == 0.0 or now - start > self.window_s:
            self._fails = (1, now)
            return
        count += 1
        self._fails = (count, start)
        if count >= self.consecutive_fail_limit:
            self._blocked_until = now + self.cooldown_s


