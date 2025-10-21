from __future__ import annotations

from typing import Any, Dict
from agents import function_tool
from adapters import AdapterFactory

@function_tool(name="get_wallet_balances", description="Obtiene balances de la wallet (nativo y todos los tokens) usando el adaptador del protocolo.")
def get_wallet_balances(*, protocol: str, project_root: str = "/root/Repositorios/ild") -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    state = adapter.wallet_state()
    return {"ok": True, "data": state}

