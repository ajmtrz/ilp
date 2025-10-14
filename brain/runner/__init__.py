from __future__ import annotations

from typing import Dict, Any

from ..adapters import AdapterFactory
from ..tools.registry import ToolRegistry
from ..tools import (
    tool_open_position, tool_increase_liquidity, tool_decrease_liquidity,
    tool_collect_fees, tool_close_position, tool_swap,
    tool_get_pool_state, tool_get_position_state, tool_get_wallet_state,
)
from ..agents.brain_agent import BrainAgent
from ..adapters.common.config import get_project_root, load_project_env, configure_logging
import yaml
from ..policies.plan import plan_actions
from ..logs.metrics import Metrics


def build_runtime() -> Dict[str, Any]:
    project_root = get_project_root(__file__)
    load_project_env(project_root)
    configure_logging()
    factory = AdapterFactory(project_root=project_root)
    registry = ToolRegistry()
    # Registrar herramientas
    registry.register("open_position", lambda p: tool_open_position(p, factory))
    registry.register("increase_liquidity", lambda p: tool_increase_liquidity(p, factory))
    registry.register("decrease_liquidity", lambda p: tool_decrease_liquidity(p, factory))
    registry.register("collect_fees", lambda p: tool_collect_fees(p, factory))
    registry.register("close_position", lambda p: tool_close_position(p, factory))
    registry.register("swap", lambda p: tool_swap(p, factory))
    registry.register("get_pool_state", lambda p: tool_get_pool_state(p, factory))
    registry.register("get_position_state", lambda p: tool_get_position_state(p, factory))
    registry.register("get_wallet_state", lambda p: tool_get_wallet_state(p, factory))
    # Cargar configuración YAML del cerebro
    cfg_path = f"{project_root}/brain/config/brain.yaml"
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            brain_cfg = yaml.safe_load(f) or {}
    except Exception:
        brain_cfg = {}
    agent = BrainAgent(registry, config=brain_cfg)
    return {"agent": agent, "registry": registry, "factory": factory, "config": brain_cfg}


def plan_and_act(pool_states: Dict[str, Any], rt: Dict[str, Any] = None, wallet_states: Dict[str, Any] = None) -> Any:
    rt = rt or build_runtime()
    agent: BrainAgent = rt["agent"]
    cfg: Dict[str, Any] = rt["config"]
    actions = plan_actions(cfg, pool_states, wallet_states or {})
    metrics = Metrics()
    results = []
    for a in actions:
        intent = a.pop("intent")
        res = agent.act(intent, a)
        metrics.record("action", {"intent": intent, "ok": True})
        results.append({"intent": intent, "result": res})
    return results


def plan_preview(pool_states: Dict[str, Any], rt: Dict[str, Any] = None, wallet_states: Dict[str, Any] = None, print_json: bool = True):
    """Genera y (opcionalmente) imprime las acciones planificadas, agnóstico a protocolo.
    Útil para verificar pre-swaps y open_position antes de ejecutar.
    """
    rt = rt or build_runtime()
    cfg: Dict[str, Any] = rt["config"]
    actions = plan_actions(cfg, pool_states, wallet_states or {})
    if print_json:
        try:
            import json  # type: ignore
            print("planned_actions=", json.dumps(actions, indent=2, default=str))
        except Exception:
            print({"planned_actions": actions})
    return actions


