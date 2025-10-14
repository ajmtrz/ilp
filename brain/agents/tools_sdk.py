from __future__ import annotations

import json
from typing import Any

try:
    from agents import function_tool, RunContextWrapper  # type: ignore
except Exception as exc:  # pragma: no cover
    function_tool = None  # type: ignore
    RunContextWrapper = Any  # type: ignore

from ..runner import build_runtime
from ..tools.schemas import (
    OpenPositionParams,
    IncreaseLiquidityParams,
    DecreaseLiquidityParams,
    CollectFeesParams,
    ClosePositionParams,
    SwapParams,
    GetPoolStateParams,
    GetPositionStateParams,
)


def _ensure_runtime():
    rt = build_runtime()
    return rt["registry"]


if function_tool is not None:

    @function_tool
    def open_position(ctx: RunContextWrapper[Any], params: OpenPositionParams) -> str:
        """Abre una posición de liquidez en el protocolo indicado.

        Args:
            params: Parámetros de apertura (pool, ticks, mints, slippage).
        """
        registry = _ensure_runtime()
        res = registry.get("open_position")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def increase_liquidity(ctx: RunContextWrapper[Any], params: IncreaseLiquidityParams) -> str:
        """Aumenta liquidez en una posición existente.

        Args:
            params: Parámetros de aumento (ticks, tamaños, slippage).
        """
        registry = _ensure_runtime()
        res = registry.get("increase_liquidity")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def decrease_liquidity(ctx: RunContextWrapper[Any], params: DecreaseLiquidityParams) -> str:
        """Disminuye y/o retira liquidez de una posición.

        Args:
            params: Parámetros de retirada (pool, posición, mínimos).
        """
        registry = _ensure_runtime()
        res = registry.get("decrease_liquidity")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def collect_fees(ctx: RunContextWrapper[Any], params: CollectFeesParams) -> str:
        """Cobra fees/recompensas de una posición.

        Args:
            params: Protocolo, pool y posición.
        """
        registry = _ensure_runtime()
        res = registry.get("collect_fees")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def close_position(ctx: RunContextWrapper[Any], params: ClosePositionParams) -> str:
        """Cierra una posición (requiere liquidez 0 y fees cobrados).

        Args:
            params: Protocolo y posición.
        """
        registry = _ensure_runtime()
        res = registry.get("close_position")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def swap(ctx: RunContextWrapper[Any], params: SwapParams) -> str:
        """Ejecuta un swap exact_in entre dos mints.

        Args:
            params: Protocolo, mint_in/out, amount, slippage.
        """
        registry = _ensure_runtime()
        res = registry.get("swap")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def get_pool_state(ctx: RunContextWrapper[Any], params: GetPoolStateParams) -> str:
        """Lee el estado on-chain de una pool.

        Args:
            params: Protocolo y pool_id.
        """
        registry = _ensure_runtime()
        res = registry.get("get_pool_state")(params.model_dump())
        return json.dumps(res)

    @function_tool
    def get_position_state(ctx: RunContextWrapper[Any], params: GetPositionStateParams) -> str:
        """Lee el estado on-chain de una posición.

        Args:
            params: Protocolo y posición.
        """
        registry = _ensure_runtime()
        res = registry.get("get_position_state")(params.model_dump())
        return json.dumps(res)


