from __future__ import annotations

from typing import Dict, Any

from . import build_runtime, plan_and_act


def run_once(protocol: str, pool_id: str) -> Dict[str, Any]:
    rt = build_runtime()
    registry = rt["registry"]
    # Leer estado de pool vía herramienta
    st_res = registry.get("get_pool_state")({"protocol": protocol, "pool_id": pool_id})
    st = (st_res or {}).get("data") if isinstance(st_res, dict) else {}
    # planificar y ejecutar
    pool_states = {f"{protocol}:{pool_id}": (st or {})}
    results = plan_and_act(pool_states)
    return {"pool_state": st, "actions": results}


