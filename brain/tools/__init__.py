from __future__ import annotations

from typing import Dict, Any

from .schemas import (
    OpenPositionParams, IncreaseLiquidityParams, DecreaseLiquidityParams,
    CollectFeesParams, ClosePositionParams, SwapParams, GetPoolStateParams,
    GetPositionStateParams, ToolResult,
)
from ..adapters import AdapterFactory
from .context import ToolContext


def _adapter_for(payload: Dict[str, Any], factory: AdapterFactory):
    protocol = (payload or {}).get("protocol")
    return factory.get(protocol)


def tool_open_position(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = OpenPositionParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    res = adapter.liquidity_prepare_open(
        pool_id=args.pool_id,
        tick_lower=args.tick_lower,
        tick_upper=args.tick_upper,
        mintA=args.mint_a,
        mintB=args.mint_b,
        amount0_desired=int(args.amount0_desired or 0),
        amount1_desired=int(args.amount1_desired or 0),
        user_token_account_a=args.user_token_account_a,
        user_token_account_b=args.user_token_account_b,
        slippage_bps=args.slippage_bps,
    )
    # Guard 1: si el prepare indica canSend=False, no intentes enviar
    try:
        if isinstance(res, dict) and res.get("canSend") is False:
            return ToolResult.success({"prep": res, "send_skipped": "canSend=false"}).dict()
    except Exception:
        pass
    # Guard: no enviar si amounts efectivos son 0
    try:
        a0 = int((args.amount0_desired or 0))
        a1 = int((args.amount1_desired or 0))
        if a0 <= 0 and a1 <= 0:
            return ToolResult.success({"prep": res, "send_skipped": "amounts both zero"}).dict()
    except Exception:
        pass
    try:
        send = adapter.liquidity_send(res, wait=True)
        return ToolResult.success({"prep": res, "send": send}).dict()
    except Exception as exc:
        # Si el adapter no soporta send o falla, devolvemos al menos el prep
        return ToolResult.success({"prep": res, "send_error": str(exc)}).dict()


def tool_increase_liquidity(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = IncreaseLiquidityParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    anc = adapter.liquidity_prepare_anchor_increase(
        pool_id=args.pool_id,
        position_nft_mint=args.position_nft_mint,
        mintA=args.mint_a,
        mintB=args.mint_b,
        tick_lower=args.tick_lower,
        tick_upper=args.tick_upper,
        amountA_desired=args.amount_a_desired,
        amountB_desired=args.amount_b_desired,
        slippage_bps=args.slippage_bps,
    )
    return ToolResult.success(anc).dict()


def tool_decrease_liquidity(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = DecreaseLiquidityParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    res = adapter.liquidity_prepare_remove(
        position_nft_mint=args.position_nft_mint,
        pool_id=args.pool_id,
        slippage_bps=0,
    )
    return ToolResult.success(res).dict()


def tool_collect_fees(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = CollectFeesParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    ix = adapter.build_collect_fee_ix(args.pool_id, args.position_nft_mint) if hasattr(adapter, "build_collect_fee_ix") else None
    return ToolResult.success({"ix": ix}).dict()


def tool_close_position(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = ClosePositionParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    ix = adapter.build_close_position_ix(args.position_nft_mint)
    return ToolResult.success({"ix": ix}).dict()


def tool_swap(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = SwapParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    # Compat: algunos adapters esperan fee_bps en vez de slippage_bps
    # Para Saucerswap, dejamos que el adaptador normalice HBAR/HTS internamente.
    mint_in = args.mint_in
    mint_out = args.mint_out
    try:
        try:
            q = adapter.get_quote(mint_in, mint_out, args.amount, kind=args.kind, slippage_bps=args.slippage_bps, route_hops=args.route_hops)
        except TypeError:
            fee_bps = getattr(args, "fee_bps", None) or args.slippage_bps
            # Algunos adapters no aceptan route_hops/slippage_bps
            try:
                q = adapter.get_quote(mint_in, mint_out, args.amount, kind=args.kind, fee_bps=fee_bps, route_hops=args.route_hops)
            except TypeError:
                q = adapter.get_quote(mint_in, mint_out, args.amount, kind=args.kind, fee_bps=fee_bps)
        tx = adapter.swap_prepare(q)
        try:
            send = adapter.swap_send(tx, wait=True)
            return ToolResult.success({"quote": q, "tx": tx, "send": send}).dict()
        except Exception as exc:
            return ToolResult.success({"quote": q, "tx": tx, "send_error": str(exc)}).dict()
    except Exception as exc:
        return ToolResult.failure(f"swap failed: {exc}").dict()


def tool_get_pool_state(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = GetPoolStateParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    # Delegar enriquecimiento a adaptadores si disponen de método dedicado
    if (payload or {}).get("protocol") in ("raydium", "saucerswap") and hasattr(adapter, "get_pool_state_enriched"):
        try:
            st = adapter.get_pool_state_enriched(args.pool_id)
        except Exception:
            pass
    return ToolResult.success(st if isinstance(st, dict) else {"value": st}).dict()


def tool_get_position_state(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    args = GetPositionStateParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    if hasattr(adapter, "check_position_exists_tool"):
        st = adapter.check_position_exists_tool(args.position_nft_mint)
    else:
        st = {}
    return ToolResult.success(st if isinstance(st, dict) else {"value": st}).dict()


# ---------------- Wallet state (agnóstico) ----------------
def tool_get_wallet_state(payload: Dict[str, Any], factory: AdapterFactory) -> Dict[str, Any]:
    """Devuelve el estado de la wallet de forma agnóstica por protocolo.
    Entrada: { protocol: "raydium"|"saucerswap", tokens?: [mints/ids opcionales] }
    Salida: { balances: { tokenId: { raw:int, decimals:int, symbol?:str } }, accounts?: {...} }
    """
    protocol = (payload or {}).get("protocol")
    adapter = factory.get(protocol)
    result: Dict[str, Any] = {"balances": {}}
    # Saucerswap: existe get_balances(HTS ids)
    if protocol == "saucerswap":
        # Delegar en el adaptador
        try:
            state = adapter.wallet_state()
            return ToolResult.success(state if isinstance(state, dict) else {"value": state}).dict()
        except Exception as exc:
            return ToolResult.failure(f"wallet_state saucerswap error: {exc}").dict()
    # Raydium/Solana: derivar ATAs para mints opcionales y leer balances
    if protocol == "raydium":
        tokens = (payload or {}).get("tokens") or []
        # Autodetección completa si no se pasan tokens: delegar en adapter
        if not tokens:
            try:
                state = adapter.wallet_state()
                return ToolResult.success(state if isinstance(state, dict) else {"value": state}).dict()
            except Exception as exc:
                return ToolResult.failure(f"wallet_state raydium error: {exc}").dict()
        # Lista explícita de mints
        balances: Dict[str, Any] = {}
        for mint in tokens:
            try:
                ata = adapter._derive_ata(adapter.owner_pubkey, mint)  # type: ignore[attr-defined]
                raw = adapter._get_token_account_balance_int(ata)  # type: ignore[attr-defined]
                balances[mint] = {"raw": int(raw or 0)}
            except Exception:
                balances[mint] = {"raw": 0}
        result["balances"] = balances
        return ToolResult.success(result).dict()
    return ToolResult.failure("protocol no soportado en wallet_state").dict()


