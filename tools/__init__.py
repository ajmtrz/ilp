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


def collect_position_rewards(*, protocol: str, project_root: str = "/root/Repositorios/ild", position_id: str, pool_id: Optional[str] = None) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.collect_rewards(pool_id=pool_id, position_id=position_id)


def execute_swap(*, protocol: str, project_root: str = "/root/Repositorios/ild", params: Dict[str, Any]) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.swap(params)  # type: ignore


def list_positions(*, protocol: str, project_root: str = "/root/Repositorios/ild") -> Dict[str, Any]:
    """Lista posiciones de liquidez de la wallet del adaptador."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.list_positions()


def get_pool_info(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str) -> Dict[str, Any]:
    """Obtiene metadatos normalizados de la pool: mints, fee_bps, tick_spacing, precio/tick."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.get_pool_info(pool_id)


def get_liquidity_quote(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str, range_spec: Dict[str, Any], amounts: Dict[str, Any], slippage_bps: int = 50) -> Dict[str, Any]:
    """Devuelve cotización para abrir/ajustar liquidez en un rango o ticks dados."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    # Normalizar inputs: o ticks {lower,upper} o rango {center,width_*}
    ticks = range_spec.get("ticks") or {k: range_spec.get(k) for k in ("lower", "upper") if k in range_spec}
    if ticks and all(k in ticks for k in ("lower", "upper")):
        if hasattr(adapter, "liquidity_quote_by_ticks"):
            return adapter.liquidity_quote_by_ticks(pool_id=pool_id, tick_lower=int(ticks["lower"]), tick_upper=int(ticks["upper"]), amount0_desired=int(amounts.get("amount0", 0) or 0), amount1_desired=int(amounts.get("amount1", 0) or 0), slippage_bps=int(slippage_bps))
    # Si no hay ticks, dejar que el adaptador decida según rango (si soporta)
    if hasattr(adapter, "liquidity_quote"):
        return adapter.liquidity_quote(pool_id=pool_id, range_spec=range_spec, amounts=amounts, slippage_bps=int(slippage_bps))
    return {"ok": False, "error": "get_liquidity_quote no soportado"}


def decide_range_to_ticks(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str, range_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Convierte una decisión de rango en ticks válidos (alineados a tick_spacing)."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "range_to_ticks"):
        return adapter.range_to_ticks(pool_id=pool_id, range_spec=range_spec)
    # Si el adaptador no expone el helper, intentar con get_pool_info para snap manual
    try:
        info = get_pool_info(protocol=protocol, project_root=project_root, pool_id=pool_id)
        spacing = int((((info.get("data") or {}).get("ammConfig") or {}).get("tickSpacing") or ((info.get("data") or {}).get("tick_spacing") or 1)))
        center = int(range_spec.get("center_tick") or 0)
        width = int(range_spec.get("width_ticks") or 0)
        lower = center - width // 2
        upper = center + width // 2
        def snap(x: int) -> int:
            m = x % spacing
            return x - m
        tl, tu = snap(lower), snap(upper)
        return {"ok": True, "ticks": {"lower": tl, "upper": tu}, "snapped": True}
    except Exception as exc:
        return {"ok": False, "error": f"no disponible: {exc}"}


def open_position(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str, ticks: Dict[str, int], amounts: Dict[str, int], slippage_bps: int = 50) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "open_position"):
        return adapter.open_position(pool_id=pool_id, ticks=ticks, amounts=amounts, slippage_bps=int(slippage_bps))
    # Raydium/SaucerSwap expusieron flujos previos; mantener compatibilidad mínima
    if hasattr(adapter, "liquidity_prepare") and hasattr(adapter, "clmm_send"):
        quote = adapter.liquidity_quote_by_ticks(pool_id=pool_id, tick_lower=int(ticks["lower"]), tick_upper=int(ticks["upper"]), amount0_desired=int(amounts.get("amount0", 0) or 0), amount1_desired=int(amounts.get("amount1", 0) or 0), slippage_bps=int(slippage_bps))
        prep = adapter.liquidity_prepare(quote)
        return adapter.clmm_send(prep)
    return {"ok": False, "error": "open_position no soportado"}


def increase_liquidity(*, protocol: str, project_root: str = "/root/Repositorios/ild", position_id: str, amounts: Dict[str, int], slippage_bps: int = 50) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "increase_liquidity"):
        return adapter.increase_liquidity(position_id=position_id, amounts=amounts, slippage_bps=int(slippage_bps))
    return {"ok": False, "error": "increase_liquidity no soportado"}


def decrease_liquidity(*, protocol: str, project_root: str = "/root/Repositorios/ild", position_id: str, share_or_amounts: Dict[str, Any], slippage_bps: int = 50) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "decrease_liquidity"):
        return adapter.decrease_liquidity(position_id=position_id, share_or_amounts=share_or_amounts, slippage_bps=int(slippage_bps))
    return {"ok": False, "error": "decrease_liquidity no soportado"}


def close_position(*, protocol: str, project_root: str = "/root/Repositorios/ild", position_id: str, slippage_bps: int = 50) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "close_position"):
        return adapter.close_position(position_id=position_id, slippage_bps=int(slippage_bps))
    return {"ok": False, "error": "close_position no soportado"}
