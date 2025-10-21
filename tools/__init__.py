from __future__ import annotations

from typing import Any, Dict, List, Optional
from adapters import AdapterFactory

def get_wallet_balances(*, protocol: str, project_root: str = "/root/Repositorios/ild") -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    state = adapter.wallet_state()
    return {"ok": True, "data": state}


def get_pool_positions_status(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: Optional[str] = None, positions: Optional[List[str]] = None) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.positions_status(pool_id=pool_id, positions=positions)

