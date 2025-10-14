from __future__ import annotations

from typing import Dict, Any

from ..tools.registry import ToolRegistry
from ..policies.risk import RiskManager
from ..policies.circuit_breakers import CircuitBreakers
import logging
import time


class BrainAgent:
    """Esqueleto del agente: selecciona herramienta y ejecuta tras validación de riesgo.
    La integración con OpenAI Agents SDK se hará en el runner.
    """

    def __init__(self, registry: ToolRegistry, config: Dict[str, Any]) -> None:
        self.registry = registry
        self.config = config or {}
        self.risk = RiskManager(self.config)
        self.cb = CircuitBreakers(self.config)
        self.logger = logging.getLogger("BrainAgent")

    def act(self, intent: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        proposal = dict(payload or {})
        # Validación previa
        self.risk.validate(intent, proposal)
        self.cb.before_action()
        try:
            t0 = time.time()
            # Si el intent es open_position y hay un pipeline de swaps previo, ejecútalos primero
            if intent == "open_position" and isinstance(proposal.get("pre_swaps"), list):
                for s in proposal.get("pre_swaps"):
                    try:
                        self.risk.validate("swap", s)
                        swap_tool = self.registry.get("swap")
                        _ = swap_tool(s)
                    except Exception:
                        # Si un swap falla, abortar la operación principal
                        raise
            tool = self.registry.get(intent)
            res = tool(proposal)
            dt = (time.time() - t0) * 1000.0
            try:
                self.logger.info("act intent=%s ok dt_ms=%.1f", intent, dt)
            except Exception:
                pass
            self.cb.on_success()
            return res
        except Exception:
            self.cb.on_failure()
            try:
                self.logger.exception("act intent=%s failed", intent)
            except Exception:
                pass
            raise


