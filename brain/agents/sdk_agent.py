from __future__ import annotations

from typing import Any, Dict, Optional, List, Callable

try:
    from agents import Agent, Runner  # type: ignore
    try:
        from agents import Guardrails, Sessions, Handoffs, Tracing  # type: ignore
    except Exception:  # pragma: no cover
        Guardrails = None  # type: ignore
        Sessions = None  # type: ignore
        Handoffs = None  # type: ignore
        Tracing = None  # type: ignore
except Exception as exc:  # pragma: no cover
    Agent = None  # type: ignore
    Runner = None  # type: ignore
    Guardrails = None  # type: ignore
    Sessions = None  # type: ignore
    Handoffs = None  # type: ignore
    Tracing = None  # type: ignore

from ..runner import build_runtime
from .provider import get_model_settings
from .tools_sdk import (
    open_position as ft_open_position,
    increase_liquidity as ft_increase_liquidity,
    decrease_liquidity as ft_decrease_liquidity,
    collect_fees as ft_collect_fees,
    close_position as ft_close_position,
    swap as ft_swap,
    get_pool_state as ft_get_pool_state,
    get_position_state as ft_get_position_state,
)


def build_agents_sdk(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Construye un Agent del OpenAI Agents SDK con herramientas LP.
    Requiere dependencia 'openai-agents' instalada. Usa el runtime local (registry/factory).
    """
    if Agent is None or Runner is None:
        raise RuntimeError("Falta dependencia openai-agents (agents). Instala 'openai-agents'.")

    rt = build_runtime()
    registry = rt["registry"]
    brain_cfg = rt["agent"].config if hasattr(rt.get("agent"), "config") else {}

    # Wrappers de herramientas para el SDK (cada función recibe un dict tipado por el LLM)
    def oa_open_position(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("open_position")(dict(params or {}))

    def oa_increase_liquidity(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("increase_liquidity")(dict(params or {}))

    def oa_decrease_liquidity(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("decrease_liquidity")(dict(params or {}))

    def oa_collect_fees(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("collect_fees")(dict(params or {}))

    def oa_close_position(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("close_position")(dict(params or {}))

    def oa_swap(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("swap")(dict(params or {}))

    def oa_get_pool_state(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("get_pool_state")(dict(params or {}))

    def oa_get_position_state(params: Dict[str, Any]) -> Dict[str, Any]:
        return registry.get("get_position_state")(dict(params or {}))

    # Guardrails: validaciones básicas contra brain.yaml
    gr_list: List[Callable[..., Any]] = []
    if Guardrails is not None:
        def validate_protocol(params: Dict[str, Any]) -> None:
            prot = (params or {}).get("protocol")
            enabled = ((brain_cfg.get("protocols") or {}).get(str(prot or "")) or {}).get("enabled")
            if not enabled:
                raise ValueError(f"Protocolo no habilitado: {prot}")

        def validate_slippage(params: Dict[str, Any]) -> None:
            limits = brain_cfg.get("limits") or {}
            mx = limits.get("slippage_bps_max")
            if mx is None:
                return
            bps = int((params or {}).get("slippage_bps", 0))
            if bps > int(mx):
                raise ValueError(f"slippage_bps {bps} > max {mx}")

        gr_list = [validate_protocol, validate_slippage]

    # Handoff: agente delegado para swaps
    swap_agent = None
    if Agent is not None:
        swap_agent = Agent(
            name="SwapExecutor",
            instructions="Ejecuta swaps con controles mínimos de slippage y reporta resultado.",
            tools=[lambda p: registry.get("swap")(dict(p or {}))],
        )

    model_settings = get_model_settings(brain_cfg)

    agent = Agent(
        name="LPBrain",
        instructions=(
            "Eres un orquestador de provisión de liquidez agnóstico a protocolo. "
            "Usa las herramientas para abrir, ajustar y cerrar posiciones con límites de riesgo y CB."
        ),
        tools=[
            ft_open_position,
            ft_increase_liquidity,
            ft_decrease_liquidity,
            ft_collect_fees,
            ft_close_position,
            ft_swap,
            ft_get_pool_state,
            ft_get_position_state,
        ],
        guardrails=gr_list if gr_list else None,
        handoffs=[{"name": "swap", "agent": swap_agent}] if swap_agent is not None else None,
        model_settings=model_settings or None,
    )
    # Sessions/Tracing
    sess = None
    tracer = None
    if Sessions is not None and session_id:
        try:
            sess = Sessions.Session(id=session_id)  # type: ignore[attr-defined]
        except Exception:
            sess = None
    if Tracing is not None:
        try:
            tracer = Tracing.Tracer()  # type: ignore[attr-defined]
        except Exception:
            tracer = None

    return {"agent": agent, "runner": Runner, "session": sess, "tracer": tracer}


