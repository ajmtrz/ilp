from __future__ import annotations

from typing import Dict, Any, List
import math


def choose_pools(brain_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Selecciona pools habilitadas desde brain.yaml (placeholder: retorna todas con config)."""
    out: List[Dict[str, Any]] = []
    protocols = (brain_cfg or {}).get("protocols") or {}
    for prot, pcfg in protocols.items():
        if not pcfg or not pcfg.get("enabled"):
            continue
        for pid, p in (pcfg.get("pools") or {}).items():
            out.append({"protocol": prot, "pool_id": pid, "cfg": p or {}})
    return out


def compute_range(tick: int, sigma_ticks: int) -> Dict[str, int]:
    """Define rango alrededor del tick usando sigma (placeholder)."""
    width = max(10, int(sigma_ticks or 10))
    return {"lower": tick - width, "upper": tick + width}


def plan_actions(brain_cfg: Dict[str, Any], pool_states: Dict[str, Dict[str, Any]], wallet_states: Dict[str, Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Genera propuestas de acciones sólo para pools con estado disponible.
    Incluye mints cuando sea posible para cumplir la interfaz de open_position.
    """
    proposals: List[Dict[str, Any]] = []
    wallet_states = wallet_states or {}
    for item in choose_pools(brain_cfg):
        prot = item["protocol"]
        pid = item["pool_id"]
        key = f"{prot}:{pid}"
        st = (pool_states.get(key) or {})
        if not st:
            # saltar pools sin estado en esta iteración
            continue
        tick = int(st.get("tick_current_index") or st.get("tickCurrentIndex") or 0)
        sigma_ticks = int(st.get("sigma_ticks", 10))
        rng = compute_range(tick, sigma_ticks)
        # Alinear a tickSpacing o usar rango porcentual para Raydium (mejor para budgets pequeños)
        try:
            spacing = int(st.get("tickSpacing") or st.get("tick_spacing") or 1)
            # Si Raydium, permitir override por porcentaje (range_pct); defecto 5%
            if prot == "raydium":
                pools_cfg = ((brain_cfg.get("protocols") or {}).get(prot) or {}).get("pools") or {}
                pcfg = pools_cfg.get(pid) or {}
                pct = pcfg.get("range_pct")
                try:
                    pct = float(pct) if pct is not None else 0.05
                except Exception:
                    pct = 0.05
                # Δtick ≈ ln(1+pct)/ln(1.0001)
                try:
                    delta_tick = int(math.log(1.0 + max(0.0001, pct)) / math.log(1.0001))
                except Exception:
                    delta_tick = 500
                lo = tick - delta_tick
                hi = tick + delta_tick
                if spacing > 1:
                    def snap_down(x: int, s: int) -> int:
                        return (x // s) * s
                    def snap_up(x: int, s: int) -> int:
                        return ((x + s - 1) // s) * s
                    lo = snap_down(lo, spacing)
                    hi = snap_up(hi, spacing)
                if hi <= lo:
                    hi = lo + max(1, spacing)
                rng = {"lower": lo, "upper": hi}
            else:
                if spacing > 1:
                    def snap_down(x: int, s: int) -> int:
                        return (x // s) * s
                    def snap_up(x: int, s: int) -> int:
                        return ((x + s - 1) // s) * s
                    lo = snap_down(rng["lower"], spacing)
                    hi = snap_up(rng["upper"], spacing)
                    if hi <= lo:
                        hi = lo + spacing
                    rng = {"lower": lo, "upper": hi}
        except Exception:
            pass
        # Sizing desde budget si está configurado
        pools_cfg = ((brain_cfg.get("protocols") or {}).get(prot) or {}).get("pools") or {}
        pcfg = pools_cfg.get(pid) or {}
        budget_usd = float(pcfg.get("budget_usd")) if pcfg.get("budget_usd") is not None else 0.0
        min_notional = float(pcfg.get("min_notional")) if pcfg.get("min_notional") is not None else 0.0
        weights = composition_v3_for_range(tick, rng["lower"], rng["upper"])
        sized = size_amounts_from_budget(budget_usd, weights, st, min_notional_usd=min_notional)

        # Inferencia de mints por protocolo
        mint_a = None
        mint_b = None
        if prot == "saucerswap":
            try:
                t0 = st.get("token0") or st.get("tokenA") or {}
                t1 = st.get("token1") or st.get("tokenB") or {}
                mint_a = t0.get("id") if isinstance(t0, dict) else None
                mint_b = t1.get("id") if isinstance(t1, dict) else None
            except Exception:
                pass
        elif prot == "raydium":
            # claves comunes en estado de pool Raydium decodificado
            for k0, k1 in (("tokenMint0", "tokenMint1"), ("token_mint_0", "token_mint_1"), ("mint0", "mint1"), ("mintA", "mintB")):
                m0 = st.get(k0)
                m1 = st.get(k1)
                if isinstance(m0, str) and isinstance(m1, str):
                    mint_a, mint_b = m0, m1
                    break

        proposal = {
            "intent": "open_position",
            "protocol": prot,
            "pool_id": pid,
            "tick_lower": rng["lower"],
            "tick_upper": rng["upper"],
            "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
        }
        # Inyectar amounts si existen
        if sized:
            proposal.update({
                "amount0_desired": int(sized.get("amount0_desired", 0)),
                "amount1_desired": int(sized.get("amount1_desired", 0)),
            })
        # Pre-swaps si el inventario no alcanza (adjuntar a la propuesta)
        pre_swaps = []
        try:
            ws_bal = (wallet_states.get(prot) or {}).get("balances") or {}
        except Exception:
            ws_bal = {}
        t0 = (st.get("token0") or st.get("tokenA") or {})
        t1 = (st.get("token1") or st.get("tokenB") or {})
        try:
            dec0 = int(t0.get("decimals", 0) or 0)
            dec1 = int(t1.get("decimals", 0) or 0)
            px0 = float(t0.get("priceUsd") or 0.0)
            px1 = float(t1.get("priceUsd") or 0.0)
            need0 = int(sized.get("amount0_desired", 0))
            need1 = int(sized.get("amount1_desired", 0))
            have0 = int(((ws_bal.get(mint_a) or {}).get("raw", 0)) if mint_a else 0)
            have1 = int(((ws_bal.get(mint_b) or {}).get("raw", 0)) if mint_b else 0)
            def0 = max(0, need0 - have0)
            def1 = max(0, need1 - have1)
            fee_bps_swap = None
            try:
                fee_bps_swap = int(st.get("fee")) if st.get("fee") is not None else None
            except Exception:
                fee_bps_swap = None
            # Regla WHBAR: si uno de los tokens es WHBAR, no planificar swap para ese lado (el mint cubrirá con msg.value)
            is_wh0 = bool(t0.get("isWhbar"))
            is_wh1 = bool(t1.get("isWhbar"))
            # Saucerswap: si falta el lado no-WHBAR y hay HBAR, usar exact_out desde HBAR por el déficit exacto
            if prot == "saucerswap":
                try:
                    hbar_tb = int((wallet_states.get("saucerswap") or {}).get("native", {}).get("HBAR", 0))
                except Exception:
                    hbar_tb = 0
                planning_buffer_bps = int((brain_cfg.get("limits") or {}).get("planning_buffer_bps", 100))
                if def0 > 0 and not is_wh0 and hbar_tb > 0 and isinstance(mint_a, str):
                    buf_out0 = int(math.ceil(def0 * (10000 + planning_buffer_bps) / 10000.0))
                    swap_intent = {
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": "HBAR",
                        "mint_out": mint_a,
                        "amount": int(buf_out0),  # exact_out con buffer para evitar segunda pasada
                        "kind": "exact_out",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    }
                    if fee_bps_swap is not None:
                        swap_intent["fee_bps"] = int(fee_bps_swap)
                    pre_swaps.append(swap_intent)
                    # Evitar añadir también un exact_in para este lado
                    def0 = 0
                if def1 > 0 and not is_wh1 and hbar_tb > 0 and isinstance(mint_b, str):
                    buf_out1 = int(math.ceil(def1 * (10000 + planning_buffer_bps) / 10000.0))
                    swap_intent = {
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": "HBAR",
                        "mint_out": mint_b,
                        "amount": int(buf_out1),
                        "kind": "exact_out",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    }
                    if fee_bps_swap is not None:
                        swap_intent["fee_bps"] = int(fee_bps_swap)
                    pre_swaps.append(swap_intent)
                    def1 = 0
            # Raydium: si falta cualquier lado y hay SOL, usar exact_out desde SOL por el déficit exacto
            if prot == "raydium":
                try:
                    sol_lamports = int((wallet_states.get("raydium") or {}).get("native", {}).get("SOL", 0))
                except Exception:
                    sol_lamports = 0
                planning_buffer_bps = int((brain_cfg.get("limits") or {}).get("planning_buffer_bps", 100))
                # Evitar swaps SOL->SOL: si el token de salida ya es SOL (WSOL mint), no planificar swap
                if def0 > 0 and sol_lamports > 0 and isinstance(mint_a, str) and mint_a != "So11111111111111111111111111111111111111112":
                    buf_out0 = int(math.ceil(def0 * (10000 + planning_buffer_bps) / 10000.0))
                    swap_intent = {
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": "So11111111111111111111111111111111111111112",  # SOL (WSOL mint)
                        "mint_out": mint_a,
                        "amount": int(buf_out0),  # exact_out con buffer
                        "kind": "exact_out",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    }
                    pre_swaps.append(swap_intent)
                    def0 = 0
                if def1 > 0 and sol_lamports > 0 and isinstance(mint_b, str) and mint_b != "So11111111111111111111111111111111111111112":
                    buf_out1 = int(math.ceil(def1 * (10000 + planning_buffer_bps) / 10000.0))
                    swap_intent = {
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": "So11111111111111111111111111111111111111112",
                        "mint_out": mint_b,
                        "amount": int(buf_out1),
                        "kind": "exact_out",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    }
                    pre_swaps.append(swap_intent)
                    def1 = 0
            if def0 > 0 and not is_wh0 and px0 > 0 and px1 > 0 and isinstance(mint_a, str) and isinstance(mint_b, str):
                # exact_in robusto: usar hasta have1 para cubrir parte del déficit de token0
                in1 = int((def0 / (10 ** max(dec0, 0))) * (10 ** dec1) * (px0 / max(px1, 1e-9)))
                amt_in = int(min(max(in1, 1), have1)) if have1 > 0 else 0
                if amt_in > 0:
                    swap_intent = {
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": mint_b,
                        "mint_out": mint_a,
                        "amount": int(amt_in),  # exact_in: amount es input disponible
                        "kind": "exact_in",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    }
                    if prot == "saucerswap" and fee_bps_swap is not None:
                        swap_intent["fee_bps"] = int(fee_bps_swap)
                    pre_swaps.append(swap_intent)
            if def1 > 0 and not is_wh1 and px0 > 0 and px1 > 0 and isinstance(mint_a, str) and isinstance(mint_b, str):
                in0 = int((def1 / (10 ** max(dec1, 0))) * (10 ** dec0) * (px1 / max(px0, 1e-9)))
                amt_in = int(min(max(in0, 1), have0)) if have0 > 0 else 0
                if amt_in > 0:
                    swap_intent = {
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": mint_a,
                        "mint_out": mint_b,
                        "amount": int(amt_in),
                        "kind": "exact_in",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    }
                    if prot == "saucerswap" and fee_bps_swap is not None:
                        swap_intent["fee_bps"] = int(fee_bps_swap)
                    pre_swaps.append(swap_intent)
            # Balanceo opcional: si se habilita y solo hay SOL, forzar exact_out hacia el token faltante hasta amounts deseados
            try:
                pools_cfg = ((brain_cfg.get("protocols") or {}).get(prot) or {}).get("pools") or {}
                pcfg = pools_cfg.get(pid) or {}
                balance_before = bool(pcfg.get("balance_before_mint", False))
            except Exception:
                balance_before = False
            if prot == "raydium" and balance_before and isinstance(mint_a, str) and isinstance(mint_b, str):
                try:
                    sol_lamports = int((wallet_states.get("raydium") or {}).get("native", {}).get("SOL", 0))
                except Exception:
                    sol_lamports = 0
                planning_buffer_bps = int((brain_cfg.get("limits") or {}).get("planning_buffer_bps", 100))
                # Si falta token A, plan exact_out desde SOL
                if def0 > 0 and sol_lamports > 0 and mint_a != "So11111111111111111111111111111111111111112":
                    buf_out0 = int(max(1, math.ceil(def0 * (10000 + planning_buffer_bps) / 10000.0)))
                    pre_swaps.append({
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": "So11111111111111111111111111111111111111112",
                        "mint_out": mint_a,
                        "amount": int(buf_out0),
                        "kind": "exact_out",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    })
                    def0 = 0
                # Si falta token B, plan exact_out desde SOL
                if def1 > 0 and sol_lamports > 0 and mint_b != "So11111111111111111111111111111111111111112":
                    buf_out1 = int(max(1, math.ceil(def1 * (10000 + planning_buffer_bps) / 10000.0)))
                    pre_swaps.append({
                        "intent": "swap",
                        "protocol": prot,
                        "mint_in": "So11111111111111111111111111111111111111112",
                        "mint_out": mint_b,
                        "amount": int(buf_out1),
                        "kind": "exact_out",
                        "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                    })
                    def1 = 0
            # Sourcing desde nativo en Hedera: usar HBAR -> WHBAR como fuente si también falta token del otro lado
            if prot == "saucerswap":
                try:
                    # HBAR tinybars disponibles
                    hbar_tb = int((wallet_states.get("saucerswap") or {}).get("native", {}).get("HBAR", 0))
                except Exception:
                    hbar_tb = 0
                # Si aún falta tokenA (no se cubrió con exact_out), intenta abastecer desde HBAR con exact_in
                if def0 > 0 and not is_wh0 and hbar_tb > 0 and isinstance(mint_a, str):
                    # Aproximar cuánto WHBAR equivalente se necesita en tinybars (1 HBAR ~ 1 WHBAR)
                    need_tb = int((def0 / (10 ** max(dec0, 0))) * 1e8) if dec0 >= 0 else 0
                    amt_in_tb = min(max(need_tb, 1), hbar_tb)
                    if amt_in_tb > 0:
                        swap_intent = {
                            "intent": "swap",
                            "protocol": prot,
                            "mint_in": "HBAR",
                            "mint_out": mint_a,
                            "amount": int(amt_in_tb),  # exact_in: tinybars
                            "kind": "exact_in",
                            "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                        }
                        if fee_bps_swap is not None:
                            swap_intent["fee_bps"] = int(fee_bps_swap)
                        pre_swaps.append(swap_intent)
                if def1 > 0 and not is_wh1 and hbar_tb > 0 and isinstance(mint_b, str):
                    need_tb = int((def1 / (10 ** max(dec1, 0))) * 1e8) if dec1 >= 0 else 0
                    amt_in_tb = min(max(need_tb, 1), hbar_tb)
                    if amt_in_tb > 0:
                        swap_intent = {
                            "intent": "swap",
                            "protocol": prot,
                            "mint_in": "HBAR",
                            "mint_out": mint_b,
                            "amount": int(amt_in_tb),
                            "kind": "exact_in",
                            "slippage_bps": int((brain_cfg.get("limits") or {}).get("slippage_bps_max", 100)),
                        }
                        if fee_bps_swap is not None:
                            swap_intent["fee_bps"] = int(fee_bps_swap)
                        pre_swaps.append(swap_intent)
        except Exception:
            pass

        if mint_a and mint_b:
            proposal.update({"mint_a": mint_a, "mint_b": mint_b})
        if pre_swaps:
            proposal["pre_swaps"] = pre_swaps
        proposals.append(proposal)
    return proposals


def _sqrt_price_from_tick(tick: int) -> float:
    # sqrtP = (1.0001)^(tick/2)
    return math.pow(1.0001, tick / 2.0)


def composition_v3_for_range(tick_current: int, tick_lower: int, tick_upper: int) -> Dict[str, float]:
    """Devuelve pesos relativos (w0, w1) para token0/token1 en un rango v3, dados ticks.
    Simplificación: si el precio está fuera del rango, es one-sided; si está dentro, usa proporciones
    lineales en sqrtP (no ajustadas por precio fiat). Estos pesos sirven para orientar el sizing.
    """
    if tick_lower >= tick_upper:
        return {"w0": 0.5, "w1": 0.5}
    if tick_current <= tick_lower:
        return {"w0": 1.0, "w1": 0.0}
    if tick_current >= tick_upper:
        return {"w0": 0.0, "w1": 1.0}
    sA = _sqrt_price_from_tick(tick_lower)
    sB = _sqrt_price_from_tick(tick_upper)
    sP = _sqrt_price_from_tick(tick_current)
    # Pesos relativos aproximados (proporcional a cantidades de Uniswap v3)
    # w0 ~ (sB - sP) / (sB - sA)
    # w1 ~ (sP - sA) / (sB - sA)
    denom = max(1e-12, (sB - sA))
    w0 = max(0.0, min(1.0, (sB - sP) / denom))
    w1 = max(0.0, min(1.0, (sP - sA) / denom))
    s = w0 + w1
    if s <= 0:
        return {"w0": 0.5, "w1": 0.5}
    return {"w0": w0 / s, "w1": w1 / s}


def _float(x: Any, default: float = 0.0) -> float:  # type: ignore[name-defined]
    try:
        return float(x)
    except Exception:
        return default


def size_amounts_from_budget(
    budget_usd: float,
    weights: Dict[str, float],
    pool_state: Dict[str, Any],
    min_notional_usd: float = 0.0,
) -> Dict[str, int]:
    """Convierte presupuesto USD y pesos en cantidades enteras deseadas por token0/token1.
    Requiere que el estado incluya decimales y precioUsd (o equivalente) por token.
    Si falta información, retorna 0.
    """
    t0 = (pool_state.get("token0") or pool_state.get("tokenA") or {})
    t1 = (pool_state.get("token1") or pool_state.get("tokenB") or {})
    dec0 = int(t0.get("decimals", 0) or 0)
    dec1 = int(t1.get("decimals", 0) or 0)
    px0 = _float(t0.get("priceUsd"), 0.0)
    px1 = _float(t1.get("priceUsd"), 0.0)
    w0 = _float(weights.get("w0"), 0.5)
    w1 = _float(weights.get("w1"), 0.5)
    # Asignación USD por lado
    usd0 = max(0.0, budget_usd * w0)
    usd1 = max(0.0, budget_usd * w1)
    # Convertir a unidades enteras
    def to_units(usd: float, px: float, dec: int) -> int:
        if usd <= 0 or px <= 0 or dec < 0:
            return 0
        return int((usd / px) * (10 ** dec))
    a0 = to_units(usd0, px0, dec0)
    a1 = to_units(usd1, px1, dec1)
    # Enforce min_notional por lado
    if min_notional_usd > 0:
        if px0 > 0 and (a0 / (10 ** max(dec0, 0))) * px0 < min_notional_usd:
            a0 = 0
        if px1 > 0 and (a1 / (10 ** max(dec1, 0))) * px1 < min_notional_usd:
            a1 = 0
    return {"amount0_desired": a0, "amount1_desired": a1}
