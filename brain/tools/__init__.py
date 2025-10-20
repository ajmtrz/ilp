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
    # Autocompletar mints si faltan (p.ej., Raydium)
    if (payload or {}).get("protocol") == "raydium" and (not payload.get("mint_a") or not payload.get("mint_b")):
        try:
            adapter = factory.get("raydium")
            st = None
            if hasattr(adapter, "get_pool_state_enriched"):
                st = adapter.get_pool_state_enriched(payload.get("pool_id"))
            # Raydium adapter puede no exponer get_pool_state; usar get_pool_state_decoded
            if not isinstance(st, dict):
                if hasattr(adapter, "get_pool_state"):
                    st = adapter.get_pool_state(payload.get("pool_id"))
                elif hasattr(adapter, "get_pool_state_decoded"):
                    st = adapter.get_pool_state_decoded(payload.get("pool_id"))
            if isinstance(st, dict):
                # Preferir helper del adaptador para extraer mints
                if hasattr(adapter, "get_pool_mints"):
                    m0, m1 = adapter.get_pool_mints(st)  # type: ignore[attr-defined]
                    if isinstance(m0, str) and isinstance(m1, str):
                        payload["mint_a"], payload["mint_b"] = m0, m1
                if not payload.get("mint_a") or not payload.get("mint_b"):
                    for k0, k1 in ("tokenMint0","tokenMint1"), ("token_mint_0","token_mint_1"), ("mint0","mint1"), ("mintA","mintB"):
                        m0 = st.get(k0)
                        m1 = st.get(k1)
                        if isinstance(m0, str) and isinstance(m1, str):
                            payload["mint_a"], payload["mint_b"] = m0, m1
                            break
        except Exception:
            pass
    args = OpenPositionParams(**payload)
    _ = ToolContext({})
    adapter = factory.get(args.protocol)
    if args.protocol == "raydium":
        # Si no llegan cantidades deseadas, usa balances actuales de las ATAs del usuario
        amt0 = int(args.amount0_desired or 0)
        amt1 = int(args.amount1_desired or 0)
        if amt0 <= 0:
            try:
                if args.mint_a == adapter.SOL_MINT:
                    amt0 = int(adapter._get_native_sol_balance_int() or 0)
                else:
                    ata_a = adapter._derive_ata(adapter.owner_pubkey, args.mint_a)
                    bal_ata = int(adapter._get_token_account_balance_int(ata_a) or 0) if ata_a else 0
                    if bal_ata > 0:
                        amt0 = bal_ata
                    else:
                        amt0 = int(getattr(adapter, "_get_token_balance_sum_by_mint")(args.mint_a) or 0)
            except Exception:
                pass
        if amt1 <= 0:
            try:
                if args.mint_b == adapter.SOL_MINT:
                    amt1 = int(adapter._get_native_sol_balance_int() or 0)
                else:
                    ata_b = adapter._derive_ata(adapter.owner_pubkey, args.mint_b)
                    bal_ata_b = int(adapter._get_token_account_balance_int(ata_b) or 0) if ata_b else 0
                    if bal_ata_b > 0:
                        amt1 = bal_ata_b
                    else:
                        amt1 = int(getattr(adapter, "_get_token_balance_sum_by_mint")(args.mint_b) or 0)
            except Exception:
                pass
        # Usar el mismo flujo Anchor que la celda dedicada, sin ambigüedades
        res = adapter.liquidity_prepare_anchor_open(
            mintA=args.mint_a,
            mintB=args.mint_b,
            pool_id=args.pool_id,
            tick_lower=args.tick_lower,
            tick_upper=args.tick_upper,
            amountA_desired=int(amt0),
            amountB_desired=int(amt1),
            slippage_bps=args.slippage_bps,
        )
    else:
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
    # Guard: no enviar si amounts 0 (solo aplica a protocolos que lo requieren; NO para Raydium)
    if args.protocol != "raydium":
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
    st = None
    if (payload or {}).get("protocol") in ("raydium", "saucerswap") and hasattr(adapter, "get_pool_state_enriched"):
        try:
            st = adapter.get_pool_state_enriched(args.pool_id)
        except Exception as exc:
            return ToolResult.failure(f"get_pool_state error: {exc}").dict()
    else:
        try:
            st = adapter.get_pool_state(args.pool_id) if hasattr(adapter, "get_pool_state") else None
        except Exception as exc:
            return ToolResult.failure(f"get_pool_state error: {exc}").dict()
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
                if mint == adapter.SOL_MINT:  # type: ignore[attr-defined]
                    raw = int(getattr(adapter, "_get_native_sol_balance_int")() or 0)
                    balances[mint] = {"raw": raw}
                else:
                    ata = adapter._derive_ata(adapter.owner_pubkey, mint)  # type: ignore[attr-defined]
                    raw_ata = int(adapter._get_token_account_balance_int(ata) or 0) if ata else 0  # type: ignore[attr-defined]
                    if raw_ata > 0:
                        balances[mint] = {"raw": raw_ata}
                    else:
                        total = int(getattr(adapter, "_get_token_balance_sum_by_mint")(mint) or 0)
                        balances[mint] = {"raw": total}
            except Exception:
                balances[mint] = {"raw": 0}
        result["balances"] = balances
        return ToolResult.success(result).dict()
    return ToolResult.failure("protocol no soportado en wallet_state").dict()


