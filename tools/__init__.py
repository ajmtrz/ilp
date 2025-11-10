from __future__ import annotations

from typing import Any, Dict, List, Optional
from adapters import AdapterFactory

def get_wallet_balances(*, protocol: str, project_root: str = "/root/Repositorios/ild") -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    state = adapter.wallet_state()
    return {"ok": True, "data": state}


def list_positions(*, protocol: str, project_root: str = "/root/Repositorios/ild") -> Dict[str, Any]:
    """Lista posiciones de liquidez de la wallet del adaptador."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.list_positions()


def get_pool_positions_status(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: Optional[str] = None, position_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.positions_status(pool_id=pool_id, positions=position_ids)


def execute_swap(*, protocol: str, project_root: str = "/root/Repositorios/ild", params: Dict[str, Any]) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.swap(params)  # type: ignore


def collect_position_rewards(*, protocol: str, project_root: str = "/root/Repositorios/ild", position_id: str, pool_id: Optional[str] = None) -> Dict[str, Any]:
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.collect_rewards(pool_id=pool_id, position_id=position_id)


def get_pool_info(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str) -> Dict[str, Any]:
    """Obtiene metadatos normalizados de la pool: mints, fee_bps, tick_spacing, precio/tick."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    return adapter.get_pool_info(pool_id)


def resolve_pool_id(*, protocol: str, project_root: str = "/root/Repositorios/ild", token_a: str, token_b: str, fee_bps: int) -> Dict[str, Any]:
    """Resuelve el identificador de pool dado token A/B y fee_bps.
    Debe delegar en el adaptador (misma firma en todos los protocolos).
    """
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "resolve_pool_id"):
        return adapter.resolve_pool_id(token_a=token_a, token_b=token_b, fee_bps=int(fee_bps))
    return {"ok": False, "error": "resolve_pool_id no soportado"}


def get_pool_state(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str) -> Dict[str, Any]:
    """Obtiene estado normalizado de la pool (tick_current, tick_spacing, liquidity_global, tokens)."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    if hasattr(adapter, "get_pool_state"):
        return adapter.get_pool_state(pool_id)
    # Fallback mínimo si el adaptador aún no expone get_pool_state
    try:
        state = adapter.get_pool_state_decoded(pool_id)
        return {"ok": True, "data": state}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def get_liquidity_quote(*, protocol: str, project_root: str = "/root/Repositorios/ild", pool_id: str, range_spec: Dict[str, Any], amounts: Dict[str, Any], slippage_bps: int = 50) -> Dict[str, Any]:
    """Devuelve cotización para abrir/ajustar liquidez en un rango o ticks dados."""
    factory = AdapterFactory(project_root)
    adapter = factory.get(protocol)
    # Normalizar inputs: o ticks {lower,upper} o rango {center,width_*}
    ticks = range_spec.get("ticks") or {k: range_spec.get(k) for k in ("lower", "upper") if k in range_spec}
    if ticks and all(k in ticks for k in ("lower", "upper")):
        # Adaptar a la firma específica del adaptador de forma agnóstica
        if hasattr(adapter, "liquidity_quote_by_ticks"):
            try:
                import inspect  # lazy import
                # Obtener tokens/fee desde el estado/metadata del pool
                try:
                    st = adapter.get_pool_state(pool_id)  # normalizado si está disponible
                    st_data = st if isinstance(st, dict) else {}
                except Exception:
                    st_data = {}
                tokenA_mint = (((st_data.get("tokens") or {}).get("A") or {}).get("mint")) if isinstance(st_data, dict) else None
                tokenB_mint = (((st_data.get("tokens") or {}).get("B") or {}).get("mint")) if isinstance(st_data, dict) else None
                fee_bps_val = None
                try:
                    meta = adapter.get_pool_info(pool_id)  # puede no estar normalizado
                    # Intentar varios campos habituales
                    fee_bps_val = int(
                        (meta.get("fee_bps")
                         or (meta.get("fee") if meta.get("fee") is not None else None)
                         or ((meta.get("config") or {}).get("tradeFeeRate") and round(float((meta.get("config") or {}).get("tradeFeeRate")) / 100.0))
                         ))
                except Exception:
                    fee_bps_val = None
                fee_bps_val = int(fee_bps_val or 0)
                # Construir kwargs según firma
                fn = getattr(adapter, "liquidity_quote_by_ticks")
                sig = inspect.signature(fn)
                params = set(sig.parameters.keys())
                kwargs = {}
                # tokens
                if "mintA" in params: kwargs["mintA"] = tokenA_mint
                if "mintB" in params: kwargs["mintB"] = tokenB_mint
                if "tokenA" in params: kwargs["tokenA"] = tokenA_mint
                if "tokenB" in params: kwargs["tokenB"] = tokenB_mint
                # fee
                if "fee_bps" in params: kwargs["fee_bps"] = fee_bps_val
                # ticks
                if "tick_lower" in params: kwargs["tick_lower"] = int(ticks["lower"])
                if "tick_upper" in params: kwargs["tick_upper"] = int(ticks["upper"])
                # amounts: cubrir ambas variantes
                a0 = int(amounts.get("amount0", 0) or amounts.get("amountA", 0) or 0)
                a1 = int(amounts.get("amount1", 0) or amounts.get("amountB", 0) or 0)
                if "amount0_desired" in params: kwargs["amount0_desired"] = a0
                if "amount1_desired" in params: kwargs["amount1_desired"] = a1
                if "amountA_desired" in params: kwargs["amountA_desired"] = a0
                if "amountB_desired" in params: kwargs["amountB_desired"] = a1
                # slippage
                if "slippage_bps" in params: kwargs["slippage_bps"] = int(slippage_bps)
                # Llamada
                return fn(**kwargs)
            except Exception as exc:
                return {"ok": False, "error": f"liquidity_quote_by_ticks: {exc}"}
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
