from __future__ import annotations

from typing import Any, Dict, List, Optional
from adapters import AdapterFactory

def get_wallet_balances(*, protocol: str, project_root: str = "/root/Repositorios/ild") -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    state = adapter.wallet_state()
    return {"ok": True, "data": state}


def get_pool_positions_status(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: Optional[str] = None, position_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.positions_status(pool_id=pool_id, positions=position_ids)


def get_position_rewards(*, protocol: str, project_root: str = "/root/Repositorios/ild", position_id: str, pool_id: Optional[str] = None) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.collect_rewards(pool_id=pool_id, position_id=position_id)


def execute_swap(*, protocol: str, project_root: str = "/root/Repositorios/ild", params: Dict[str, Any]) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.swap(params)  # type: ignore

