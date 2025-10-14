from __future__ import annotations

from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel, Field, validator
from typing import Tuple


# ---------------- Generic request/response schemas (protocol-agnostic) ----------------


class OpenPositionParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    pool_id: str
    mint_a: str
    mint_b: str
    tick_lower: int
    tick_upper: int
    slippage_bps: int = Field(..., ge=0)
    amount0_desired: Optional[int] = Field(default=None, ge=0)
    amount1_desired: Optional[int] = Field(default=None, ge=0)
    with_metadata: bool = True
    base_flag: Optional[bool] = False
    user_token_account_a: Optional[str] = None
    user_token_account_b: Optional[str] = None

    @validator("tick_upper")
    def _check_ticks(cls, v, values):  # type: ignore[override]
        lower = values.get("tick_lower")
        if lower is not None and v <= lower:
            raise ValueError("tick_upper debe ser mayor que tick_lower")
        return v
    @validator("mint_b")
    def _check_mints(cls, v, values):  # type: ignore[override]
        if v and values.get("mint_a") and v == values.get("mint_a"):
            raise ValueError("mint_a y mint_b deben ser distintos")
        return v


class IncreaseLiquidityParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    pool_id: str
    position_nft_mint: str
    mint_a: str
    mint_b: str
    tick_lower: int
    tick_upper: int
    amount_a_desired: int = Field(..., ge=0)
    amount_b_desired: int = Field(..., ge=0)
    slippage_bps: int = Field(..., ge=0)

    @validator("tick_upper")
    def _check_ticks_inc(cls, v, values):  # type: ignore[override]
        lower = values.get("tick_lower")
        if lower is not None and v <= lower:
            raise ValueError("tick_upper debe ser mayor que tick_lower")
        return v
    @validator("mint_b")
    def _check_mints_inc(cls, v, values):  # type: ignore[override]
        if v and values.get("mint_a") and v == values.get("mint_a"):
            raise ValueError("mint_a y mint_b deben ser distintos")
        return v


class DecreaseLiquidityParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    pool_id: str
    position_nft_mint: str
    pct_or_liquidity: int = Field(..., ge=1)
    amount0_min: int = Field(..., ge=0)
    amount1_min: int = Field(..., ge=0)


class CollectFeesParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    pool_id: str
    position_nft_mint: str


class ClosePositionParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    position_nft_mint: str


class SwapParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    mint_in: str
    mint_out: str
    amount: int = Field(..., gt=0)
    slippage_bps: int = Field(..., ge=0)
    fee_bps: Optional[int] = Field(default=None, ge=0)
    kind: Literal["exact_in", "exact_out"] = "exact_in"
    route_hops: Optional[List[Tuple[str, int]]] = None


class GetPoolStateParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    pool_id: str


class GetPositionStateParams(BaseModel):
    protocol: Literal["raydium", "saucerswap"]
    position_nft_mint: str


class ToolResult(BaseModel):
    ok: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @classmethod
    def success(cls, data: Optional[Dict[str, Any]] = None) -> "ToolResult":
        return cls(ok=True, data=data or {})

    @classmethod
    def failure(cls, error: str) -> "ToolResult":
        return cls(ok=False, error=error)


class HealthCheck(BaseModel):
    name: str
    healthy: bool
    details: Dict[str, Any] = {}


