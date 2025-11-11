import os
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import yaml
from adapters.common.config import get_project_root, load_project_env, configure_logging, resolve_from_root

from .ClmmDecoder import ClmmDecoder


@dataclass
class RaydiumConfig:
    cluster: str
    rpc_endpoints: List[str]
    wss_endpoints: List[str]
    keypair_path: str
    program_id_clmm: str
    api_base: str
    priority_fee_tier: str


class EndpointRotator:
    """Simple failover: iterate endpoints on failure without retrying the same one."""

    def __init__(self, endpoints: List[str]):
        if not endpoints:
            raise ValueError("At least one RPC endpoint is required")
        self._endpoints = endpoints
        self._index = 0

    @property
    def current(self) -> str:
        return self._endpoints[self._index]

    def rotate(self) -> str:
        self._index = (self._index + 1) % len(self._endpoints)
        return self.current


class RaydiumAdapter:
    def __init__(self, config_path: str):
        project_root = get_project_root(__file__)
        load_project_env(project_root)
        configure_logging()
        self.logger = logging.getLogger(self.__class__.__name__)

        config_path_abs = resolve_from_root(project_root, config_path)
        with open(config_path_abs, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        try:
            sol = cfg["solana"]
            ray = cfg["raydium"]
        except Exception as exc:
            raise ValueError("Invalid configuration structure. Expected keys: solana, raydium") from exc

        self.config = RaydiumConfig(
            cluster=sol.get("cluster"),
            rpc_endpoints=sol.get("rpc_endpoints", []),
            wss_endpoints=sol.get("wss_endpoints", []),
            keypair_path=sol.get("keypair_path"),
            program_id_clmm=ray.get("program_id_clmm"),
            api_base=ray.get("api_base", "https://transaction-v1.raydium.io"),
            priority_fee_tier=str(ray.get("priority_fee_tier", "h")).lower(),
        )

        if not self.config.cluster:
            raise ValueError("solana.cluster is required")
        if not self.config.rpc_endpoints:
            raise ValueError("solana.rpc_endpoints must contain at least one endpoint")
        if not self.config.program_id_clmm:
            raise ValueError("raydium.program_id_clmm is required")
        if self.config.priority_fee_tier not in ("vh", "h", "m"):
            raise ValueError("raydium.priority_fee_tier must be one of: vh, h, m")

        self.rpc = EndpointRotator(self.config.rpc_endpoints)
        self.logger.info(
            "RaydiumAdapter inicializado (cluster=%s, rpc_endpoints=%d, api_base=%s, tx=v0, fee_tier=%s)",
            self.config.cluster,
            len(self.config.rpc_endpoints),
            self.config.api_base,
            self.config.priority_fee_tier,
        )

        idl = ClmmDecoder.fetch_idl_onchain(
            program_id=self.config.program_id_clmm,
            cluster=self.config.cluster,
            wallet_path=self.config.keypair_path,
        )
        self.decoder = ClmmDecoder(idl)

        self.owner_pubkey = self._derive_owner_from_keypair(self.config.keypair_path)
        self.SOL_MINT = "So11111111111111111111111111111111111111112"

    def _is_sol_mint(self, mint: Optional[str]) -> bool:
        try:
            return isinstance(mint, str) and mint == self.SOL_MINT
        except Exception:
            return False

    # ---------------- Tx helpers (inspección de receipts) ----------------
    def _get_transaction_parsed(self, signature: str) -> Optional[Dict[str, Any]]:
        """getTransaction(signature, jsonParsed). Devuelve result o None si falla."""
        import requests
        try:
            rpc = self.rpc.current
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "commitment": "confirmed",
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
            }
            resp = requests.post(rpc, json=payload, timeout=12)
            resp.raise_for_status()
            data = resp.json() or {}
            return data.get("result")
        except Exception as exc:
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning("getTransaction failed for %s: %s", signature, exc)
            return None

    def _extract_position_nfts_from_tx(self, tx_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extrae posibles NFT de posición (Token-2022, amount 1 con decimals 0) otorgados al owner.
        Heurística: mint con postBalance - preBalance = 1 para owner==self.owner_pubkey.
        Devuelve {nfts:[mint...], pdas:[...]}.
        """
        try:
            meta = (tx_result or {}).get("meta") or {}
            pre = meta.get("preTokenBalances") or []
            post = meta.get("postTokenBalances") or []
            def to_map(arr: List[Dict[str, Any]]) -> Dict[Tuple[str,str], Dict[str, Any]]:
                out: Dict[Tuple[str,str], Dict[str, Any]] = {}
                for it in arr:
                    try:
                        mint = it.get("mint")
                        owner = it.get("owner")
                        if mint and owner:
                            out[(str(mint), str(owner))] = it
                    except Exception:
                        continue
                return out
            pre_map = to_map(pre)
            post_map = to_map(post)
            gained: List[str] = []
            for key, post_it in post_map.items():
                mint, owner = key
                if owner != self.owner_pubkey:
                    continue
                ui = (post_it.get("uiTokenAmount") or {})
                dec = int(ui.get("decimals", 0)) if isinstance(ui.get("decimals"), (int, str)) else 0
                amt_post = int(ui.get("amount", 0)) if isinstance(ui.get("amount"), (int, str)) else 0
                pre_it = pre_map.get(key)
                amt_pre = 0
                if pre_it:
                    ui0 = (pre_it.get("uiTokenAmount") or {})
                    amt_pre = int(ui0.get("amount", 0)) if isinstance(ui0.get("amount"), (int, str)) else 0
                if dec == 0 and (amt_post - amt_pre) == 1:
                    gained.append(mint)
            pdas: List[str] = []
            for m in gained:
                try:
                    pda, _bump = self._derive_personal_position_pda(m)
                    pdas.append(pda)
                except Exception:
                    continue
            return {"nfts": gained, "pdas": pdas}
        except Exception:
            return {"nfts": [], "pdas": []}

    def _ata_exists(self, ata_pubkey: Optional[str]) -> Optional[bool]:
        """Devuelve True si la cuenta existe en RPC, False si no existe, None si error.
        Usa getAccountInfo (encoding base64) reutilizando helper existente.
        """
        try:
            if not ata_pubkey:
                return None
            b64 = self._get_account_info_base64(ata_pubkey)
            return True if b64 else False
        except Exception:
            return None

    # ---------------- CLMM: resolver pool por mints+fee ----------------
    def _clmm_fetch_pools_by_mints(self, mint1: str, mint2: str) -> List[Dict[str, Any]]:
        """Intenta obtener pools CLMM que involucren mint1 y mint2 usando la API v3.
        Retorna lista de pools (dict), o [] si no se encuentran.
        Endpoint correcto: /pools/info/mint (paginado)
        """
        import requests
        base = "https://api-v3.raydium.io"
        url = base.rstrip("/") + "/pools/info/mint"
        q = {
            "mint1": mint1,
            "mint2": mint2,
            "poolType": "concentrated",
            "poolSortField": "default",
            "sortType": "desc",
            "pageSize": 20,
            "page": 1,
        }
        try:
            r = requests.get(url, params=q, timeout=20)
            r.raise_for_status()
            data = r.json() or {}
            payload = (data.get("data") or {}) if isinstance(data, dict) else {}
            items = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(items, list):
                return items
        except Exception as exc:
            self.logger.warning("_clmm_fetch_pools_by_mints falló %s: %s", url, exc)
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("_clmm_fetch_pools_by_mints sin resultados para %s/%s", mint1, mint2)
        return []

    def _clmm_resolve_pool(self, mintA: str, mintB: str, fee_bps: int) -> Optional[Dict[str, Any]]:
        """Resuelve una pool CLMM concreta por mints y fee (bps). Devuelve el dict de la pool o None.
        La API puede devolver múltiples pools; filtramos por mints (sin importar orden) y fee.
        """
        pools = self._clmm_fetch_pools_by_mints(mintA, mintB)
        if not pools:
            return None
        target_set = {mintA, mintB}
        fee_int = int(fee_bps)
        def extract_mints(p: Dict[str, Any]) -> Optional[set]:
            # Estructura de pools/info/mint: mintA/mintB son objetos con address
            try:
                ma_obj = p.get("mintA") or {}
                mb_obj = p.get("mintB") or {}
                ma = ma_obj.get("address") or ma_obj.get("mint") or p.get("mintA")
                mb = mb_obj.get("address") or mb_obj.get("mint") or p.get("mintB")
                if ma and mb:
                    return {str(ma), str(mb)}
            except Exception:
                return None
            return None
        def extract_fee(p: Dict[str, Any]) -> Optional[int]:
            """Devuelve fee en basis points (bps, 1 bps=0.01%).
            Preferimos config.tradeFeeRate (ppm), luego feeRate (fracción), luego feeBps si existiera.
            """
            try:
                cfg = p.get("config") or {}
                tr = cfg.get("tradeFeeRate")
                if tr is not None:
                    # tradeFeeRate suele expresarse en ppm (1e6)
                    # 400 -> 0.04% -> 4 bps
                    val = float(tr)
                    return int(round(val / 100.0))
            except Exception:
                pass
            # feeRate como fracción (0.0004 => 4 bps)
            try:
                fr = p.get("feeRate")
                if fr is not None:
                    val = float(fr)
                    return int(round(val * 1e4))
            except Exception:
                pass
            # feeBps directo
            try:
                fb = p.get("feeBps")
                if fb is not None:
                    return int(fb)
            except Exception:
                pass
            return None
        def extract_tick_spacing(p: Dict[str, Any]) -> Optional[int]:
            # pools/info/mint: tickSpacing en p["config"]["tickSpacing"]
            try:
                if p.get("tickSpacing") is not None:
                    return int(p.get("tickSpacing"))
            except Exception:
                pass
            try:
                cfg = p.get("config") or {}
                if cfg.get("tickSpacing") is not None:
                    return int(cfg.get("tickSpacing"))
            except Exception:
                pass
            return None
        chosen: Optional[Dict[str, Any]] = None
        for p in pools:
            mints = extract_mints(p) or set()
            if mints != target_set:
                continue
            pf = extract_fee(p)
            if pf is None:
                # si fee no está claro, lo aceptamos como candidato pero continuamos buscando coincidencia exacta
                if chosen is None:
                    chosen = p
                continue
            if pf == fee_int:
                chosen = p
                break
        return chosen

    def _snap_tick(self, tick: int, spacing: int, mode: str = "floor") -> int:
        if not isinstance(spacing, int) or spacing <= 0:
            return int(tick)
        if mode == "ceil":
            return ((int(tick) + spacing - 1) // spacing) * spacing
        return (int(tick) // spacing) * spacing

    def open_position(
        self,
        pool_id: str,
        ticks: Dict[str, int],
        amounts: Dict[str, int],
        slippage_bps: int = 50,
    ) -> Dict[str, Any]:
        """Abre una nueva posición CLMM en una única llamada (prepara y envía).
        - Deriva mints y fee_bps desde la pool.
        - Construye quote por ticks y prepara tx V0.
        - Envía todas las transacciones resultantes en orden.
        """
        if not pool_id:
            return {"ok": False, "error": "pool_id requerido"}
        try:
            tick_lower = int(ticks.get("lower"))
            tick_upper = int(ticks.get("upper"))
        except Exception:
            return {"ok": False, "error": "ticks inválidos"}
        amount0 = int(amounts.get("amount0", 0) or amounts.get("amountA", 0) or 0)
        amount1 = int(amounts.get("amount1", 0) or amounts.get("amountB", 0) or 0)

        # Derivar mints y fee_bps desde info de la pool
        info = self.get_pool_info(pool_id) or {}
        # mints desde estado (más robusto que info plano)
        st = self.get_pool_state_decoded(pool_id) or {}
        mintA, mintB = self.get_pool_mints(st)
        if not (mintA and mintB):
            # Intentar extraer desde info si estado no las trae
            try:
                ma_obj = info.get("mintA") or {}
                mb_obj = info.get("mintB") or {}
                mintA = mintA or ma_obj.get("address") or ma_obj.get("mint")
                mintB = mintB or mb_obj.get("address") or mb_obj.get("mint")
            except Exception:
                pass
        if not (mintA and mintB):
            return {"ok": False, "error": "no se pudieron derivar los mints de la pool"}

        # fee_bps: preferir config.tradeFeeRate (ppm) -> bps; fallback a feeRate o feeBps
        fee_bps_val = None
        try:
            cfg = info.get("config") or {}
            tr = cfg.get("tradeFeeRate")
            if tr is not None:
                fee_bps_val = int(round(float(tr) / 100.0))
        except Exception:
            fee_bps_val = None
        if fee_bps_val is None:
            try:
                fr = info.get("feeRate")
                if fr is not None:
                    fee_bps_val = int(round(float(fr) * 1e4))
            except Exception:
                fee_bps_val = None
        if fee_bps_val is None:
            try:
                fb = info.get("feeBps")
                if fb is not None:
                    fee_bps_val = int(fb)
            except Exception:
                fee_bps_val = None
        fee_bps_val = int(fee_bps_val or 0)

        # Construir quote y preparar tx
        quote = self.liquidity_quote_by_ticks(
            mintA=mintA,
            mintB=mintB,
            fee_bps=fee_bps_val,
            tick_lower=tick_lower,
            tick_upper=tick_upper,
            amountA_desired=amount0,
            amountB_desired=amount1,
            slippage_bps=int(slippage_bps),
        )
        if not isinstance(quote, dict) or not quote.get("exists", True):
            return {"ok": False, "error": "liquidity_quote_by_ticks falló", "details": quote}
        prep = self.liquidity_prepare(quote)
        # Delegar el envío al pipeline que gestiona extraSigners de Anchor
        res = self.liquidity_send(prep, wait=True)
        return res

    def ensure_token_accounts(self, tokens: List[str]) -> Dict[str, Any]:
        """Comprueba ATAs para los mints indicados y crea los que falten si es posible.
        - Para SOL nativo no se crea ATA; WSOL se maneja de forma temporal en los flujos del adaptador.
        """
        created: List[Dict[str, Any]] = []
        exists: Dict[str, Any] = {}
        errs: List[Dict[str, str]] = []
        owner = self.owner_pubkey
        for mint in tokens or []:
            try:
                if self._is_sol_mint(mint):
                    exists[mint] = {"ata": None, "exists": True, "native": True}
                    continue
                ata = self._derive_ata(owner, mint)
                if not ata:
                    exists[mint] = {"ata": None, "exists": False}
                    continue
                info = self._get_account_info_base64(ata)
                if info:
                    exists[mint] = {"ata": ata, "exists": True}
                    continue
                # Crear ATA vía spl.associated_token_account
                try:
                    from solana.rpc.api import Client  # type: ignore
                    from solana.transaction import Transaction  # type: ignore
                    from solana.keypair import Keypair as SolKeypair  # type: ignore
                    from spl.token.instructions import create_associated_token_account  # type: ignore
                except Exception as exc:
                    errs.append({"mint": mint, "error": f"dependencias solana/spl faltan: {exc}"})
                    exists[mint] = {"ata": ata, "exists": False}
                    continue
                # Cargar keypair en formato solana-py
                try:
                    import json, os
                    expanded_path = os.path.expanduser(self.config.keypair_path)
                    with open(expanded_path, "r", encoding="utf-8") as f:
                        key_data = json.load(f)
                    sk = SolKeypair.from_secret_key(bytes(key_data))
                except Exception as exc:
                    errs.append({"mint": mint, "error": f"no se pudo cargar keypair: {exc}"})
                    exists[mint] = {"ata": ata, "exists": False}
                    continue
                # Construir y enviar tx legacy
                tx = Transaction()
                ix = create_associated_token_account(payer=sk.public_key, owner=sk.public_key, mint=mint)
                tx.add(ix)
                client = self._rpc_client()
                resp = client.send_transaction(tx, sk)
                created.append({"mint": mint, "ata": ata, "result": resp})
                exists[mint] = {"ata": ata, "exists": True}
            except Exception as exc:
                errs.append({"mint": str(mint), "error": str(exc)})
        ok = all(v.get("exists") for v in exists.values())
        out: Dict[str, Any] = {"ok": ok, "owner": owner, "exists": exists}
        if created:
            out["created"] = created
        if errs:
            out["errors"] = errs
        return out
    def range_to_ticks(self, pool_id: str, range_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Convierte center/width a ticks válidos alineados a tickSpacing de la pool."""
        # Determinar tick_spacing desde estado on-chain o info API
        tick_spacing = None
        try:
            st = self.get_pool_state_decoded(pool_id) or {}
            for k in ("tick_spacing", "tickSpacing", "tick_spacing_index"):
                if st.get(k) is not None:
                    try:
                        tick_spacing = int(st.get(k))
                        break
                    except Exception:
                        continue
        except Exception:
            tick_spacing = None
        if tick_spacing is None:
            try:
                info = self.get_pool_info(pool_id) or {}
                cfg = info.get("config") or {}
                if cfg.get("tickSpacing") is not None:
                    tick_spacing = int(cfg.get("tickSpacing"))
                elif info.get("tickSpacing") is not None:
                    tick_spacing = int(info.get("tickSpacing"))
            except Exception:
                tick_spacing = None
        if not isinstance(tick_spacing, int) or tick_spacing <= 0:
            tick_spacing = 1
        center = int(range_spec.get("center_tick") or 0)
        width = int(range_spec.get("width_ticks") or 0)
        lower = center - (width // 2)
        upper = center + (width // 2)
        s_lo = self._snap_tick(lower, tick_spacing, mode="floor")
        s_up = self._snap_tick(upper, tick_spacing, mode="ceil")
        snapped = (s_lo, s_up) != (lower, upper)
        if s_lo >= s_up:
            return {"ok": False, "error": "tick range colapsó tras snapping", "tick_spacing": tick_spacing}
        return {"ok": True, "ticks": {"lower": s_lo, "upper": s_up}, "snapped": snapped, "tick_spacing": tick_spacing}

    # ---------------- Liquidez CLMM: Quote por ticks ----------------
    def liquidity_quote_by_ticks(
        self,
        mintA: str,
        mintB: str,
        fee_bps: int,
        tick_lower: int,
        tick_upper: int,
        amountA_desired: int,
        amountB_desired: int,
        slippage_bps: int = 50,
        recipient: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pre-cálculo para nueva posición CLMM dado un rango de ticks y amounts deseados.
        - Valida que exista pool CLMM para (mintA,mintB,fee).
        - Calcula mínimos por slippage (cliente).
        - No consulta on-chain cantidades exactas.
        """
        if not isinstance(tick_lower, int) or not isinstance(tick_upper, int) or tick_lower >= tick_upper:
            raise ValueError("tick_lower/tick_upper inválidos (tick_lower < tick_upper)")
        recv = recipient or self.owner_pubkey
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("clmm_quote: mints A/B=%s/%s fee_bps=%s", mintA, mintB, fee_bps)
        pool = self._clmm_resolve_pool(mintA, mintB, int(fee_bps))
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("clmm_quote: resolve_pool -> %s", {k: pool.get(k) for k in ("id","feeRate","ammConfig")} if isinstance(pool, dict) else pool)
        if not pool:
            return {"exists": False, "reason": "pool no existe", "details": {"mints": [mintA, mintB], "fee_bps": int(fee_bps)}}
        # Validar/snap de ticks según tickSpacing si está disponible
        tick_spacing = None
        try:
            tick_spacing = int(
                (pool.get("ammConfig") or {}).get("tickSpacing")
                or (pool.get("config") or {}).get("tickSpacing")
                or pool.get("tickSpacing")
            ) if isinstance(pool, dict) else None
        except Exception:
            tick_spacing = None
        snapped_lower = int(tick_lower)
        snapped_upper = int(tick_upper)
        snapped = False
        if isinstance(tick_spacing, int) and tick_spacing > 0:
            s_lo = self._snap_tick(tick_lower, tick_spacing, mode="floor")
            s_up = self._snap_tick(tick_upper, tick_spacing, mode="ceil")
            if (s_lo, s_up) != (tick_lower, tick_upper):
                snapped_lower, snapped_upper, snapped = s_lo, s_up, True
        if snapped and snapped_lower >= snapped_upper:
            return {"exists": False, "reason": "tick range colapsó tras snapping", "details": {"tick_spacing": tick_spacing, "proposed": [snapped_lower, snapped_upper]}}
        # mínimos por slippage
        slip = max(0, int(slippage_bps))
        if slip == 0:
            a_min, b_min = 0, 0
        else:
            a_min = (int(amountA_desired) * (10000 - slip)) // 10000
            b_min = (int(amountB_desired) * (10000 - slip)) // 10000
        out = {
            "exists": True,
            "kind": "clmm_liquidity_by_ticks",
            "mints": {"mintA": mintA, "mintB": mintB},
            "fee_bps": int(fee_bps),
            "ticks": {"lower": int(snapped_lower), "upper": int(snapped_upper)},
            "amounts": {
                "amountADesired": int(amountA_desired),
                "amountBDesired": int(amountB_desired),
                "amountAMin": int(a_min),
                "amountBMin": int(b_min),
            },
            "pool": {
                "id": pool.get("id") or pool.get("poolId") or pool.get("address"),
                "raw": pool,
            },
            "slippage_bps": int(slippage_bps),
            "recipient": recv,
            "notes": [],
        }
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                "clmm_quote: ticks [%s,%s] amounts(desired)=(%s,%s) mins=(%s,%s) poolId=%s spacing=%s snapped=%s",
                out["ticks"]["lower"], out["ticks"]["upper"],
                out["amounts"]["amountADesired"], out["amounts"]["amountBDesired"],
                out["amounts"]["amountAMin"], out["amounts"]["amountBMin"], out["pool"]["id"], tick_spacing, snapped,
            )
        if self.logger.isEnabledFor(logging.DEBUG):
            try:
                self.logger.debug("clmm_quote: out=%s", {k: out[k] for k in ("fee_bps","ticks","amounts","recipient")})
            except Exception:
                pass
        return out

    # ---------------- Liquidez CLMM: Prepare (open position + add liquidity) ----------------
    def liquidity_prepare(self, quote: Dict[str, Any], compute_unit_price_micro: Optional[int] = None, compute_unit_limit: Optional[int] = None) -> Dict[str, Any]:
        """Construye transacciones V0 para abrir posición CLMM y añadir liquidez usando la Transaction API.
        - Requiere el resultado de liquidity_quote_by_ticks.
        - Devuelve {transactions:[base64...], meta:{...}} listo para firmar/enviar.
        """
        if not isinstance(quote, dict) or not quote.get("exists"):
            raise ValueError("quote inválido o pool no existe")
        kind = quote.get("kind")
        if kind != "clmm_liquidity_by_ticks":
            raise ValueError("quote.kind inesperado para CLMM")

        mints = quote.get("mints") or {}
        mintA = str(mints.get("mintA"))
        mintB = str(mints.get("mintB"))
        amounts = quote.get("amounts") or {}
        a_des = int(amounts.get("amountADesired", 0))
        b_des = int(amounts.get("amountBDesired", 0))
        a_min = int(amounts.get("amountAMin", 0))
        b_min = int(amounts.get("amountBMin", 0))
        ticks = quote.get("ticks") or {}
        t_lo = int(ticks.get("lower"))
        t_hi = int(ticks.get("upper"))
        pool = quote.get("pool") or {}
        pool_id = pool.get("id")
        if not pool_id:
            raise ValueError("pool_id ausente en quote.pool.id")
        recipient = quote.get("recipient") or self.owner_pubkey

        # Compute Budget por defecto (alineado a ejemplos de UI): 25k microLamports, 600k CUs
        # Referencia: instrucciones Compute Budget en flujo de UI
        cu_price = int(compute_unit_price_micro) if compute_unit_price_micro is not None else 25_000
        cu_limit = int(compute_unit_limit) if compute_unit_limit is not None else 600_000

        # wrapSol si participan SOL nativo en A o B
        wrap_sol = self._is_sol_mint(mintA) or self._is_sol_mint(mintB)
        # Estimar lamports a wrapear (en función del lado SOL)
        wrap_lamports = 0
        if wrap_sol:
            if self._is_sol_mint(mintA):
                wrap_lamports = int(a_des)
            elif self._is_sol_mint(mintB):
                wrap_lamports = int(b_des)

        # Comprobaciones de saldo (amigables): si no hay saldo suficiente, marcar canSend y notas
        notes: List[str] = []
        can_send: bool = True
        try:
            # Obtener balances con la API de cuentas (owner)
            # Tokens SPL (no SOL): consultamos token accounts por mint
            import requests
            rpc = self.rpc.current
            # Balance de SOL (lamports) para cubrir rent y fee
            try:
                resp = requests.post(rpc, json={"jsonrpc":"2.0","id":1,"method":"getBalance","params":[self.owner_pubkey,{"commitment":"confirmed"}]}, timeout=10)
                resp.raise_for_status()
                sol_bal = int(((resp.json() or {}).get("result") or {}).get("value", 0))
            except Exception:
                sol_bal = 0
            # Balance token A si no es SOL
            bal_a = None
            if not self._is_sol_mint(mintA):
                try:
                    ata_a = self._derive_ata(self.owner_pubkey, mintA)
                    resp = requests.post(rpc, json={"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":[ata_a,{"commitment":"confirmed"}]}, timeout=10)
                    resp.raise_for_status()
                    ui = ((resp.json() or {}).get("result") or {}).get("value") or {}
                    bal_a = int(ui.get("amount", 0))
                except Exception:
                    bal_a = None
            # Balance token B si no es SOL
            bal_b = None
            if not self._is_sol_mint(mintB):
                try:
                    ata_b = self._derive_ata(self.owner_pubkey, mintB)
                    resp = requests.post(rpc, json={"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":[ata_b,{"commitment":"confirmed"}]}, timeout=10)
                    resp.raise_for_status()
                    ui = ((resp.json() or {}).get("result") or {}).get("value") or {}
                    bal_b = int(ui.get("amount", 0))
                except Exception:
                    bal_b = None

            # Evaluar necesidades
            # SOL requerido mínimo aproximado: wrap_lamports + margen para rent/fees
            min_sol_needed = wrap_lamports
            # margen estático conservador (p.ej., ~0.03 SOL en lamports); ajustable si fuese necesario
            MARGIN_LAMPORTS = 30_000_000
            min_sol_needed += MARGIN_LAMPORTS
            if sol_bal < min_sol_needed:
                can_send = False
                notes.append(f"sol insuficiente: have={sol_bal} need>={min_sol_needed}")
            if (not self._is_sol_mint(mintA)) and (bal_a is not None) and bal_a < a_des:
                can_send = False
                notes.append(f"tokenA insuficiente: have={bal_a} need>={a_des}")
            if (not self._is_sol_mint(mintB)) and (bal_b is not None) and bal_b < b_des:
                can_send = False
                notes.append(f"tokenB insuficiente: have={bal_b} need>={b_des}")
        except Exception as exc:
            notes.append(f"balance check warn: {exc}")

        # Pre-chequeo de ATAs del owner para mintA/mintB (solo tokens no SOL)
        ata_info: Dict[str, Any] = {}
        try:
            if not self._is_sol_mint(mintA):
                ata_a = self._derive_ata(self.owner_pubkey, mintA)
                exists_a = self._ata_exists(ata_a)
                ata_info["A"] = {"ata": ata_a, "exists": exists_a}
            if not self._is_sol_mint(mintB):
                ata_b = self._derive_ata(self.owner_pubkey, mintB)
                exists_b = self._ata_exists(ata_b)
                ata_info["B"] = {"ata": ata_b, "exists": exists_b}
        except Exception as _exc_ata:
            ata_info["error"] = str(_exc_ata)

        # Construir payload para Transaction API (similar al flujo de swaps v0)
        payload = {
            "wallet": self.owner_pubkey,
            "poolId": str(pool_id),
            "tickLowerIndex": t_lo,
            "tickUpperIndex": t_hi,
            # amounts máximos a aportar (la API aplicará límites y min con slippage)
            "amountA": a_des,
            "amountB": b_des,
            "amountAMin": a_min,
            "amountBMin": b_min,
            "recipient": recipient,
            "txVersion": "V0",
            "computeBudgetConfig": {
                "microLamports": cu_price,
                "units": cu_limit,
            },
        }
        if wrap_sol:
            payload["wrapSol"] = True

        # Fallback Anchor: construir y empaquetar V0
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("clmm_prepare(anchor): poolId=%s ticks=[%s,%s] amounts=(%s,%s) mins=(%s,%s) CU(price=%s,limit=%s)",
                             pool_id, t_lo, t_hi, a_des, b_des, a_min, b_min, cu_price, cu_limit)
        anchor_open = self.liquidity_prepare_anchor_open(
            mintA=mintA, mintB=mintB, pool_id=pool_id,
            tick_lower=t_lo, tick_upper=t_hi,
            amountA_desired=a_des, amountB_desired=b_des,
            slippage_bps=quote.get("slippage_bps", 50),
            compute_unit_price_micro=cu_price, compute_unit_limit=cu_limit,
        )
        try:
            tx_b64, extra_signers = self._assemble_v0_from_anchor(anchor_open)
            meta = anchor_open.get("meta") or {}
            meta["atas"] = ata_info or None
            # Exponer anchor para que send pueda usar fallback de mint planificado
            return {"transactions": [tx_b64], "meta": meta, "canSend": can_send, "notes": notes, "extraSigners": extra_signers, "anchor": (anchor_open.get("anchor") or {})}
        except Exception as exc:
            import traceback  # type: ignore
            tb = traceback.format_exc()
            notes.append(str(exc))
            notes.append(f"trace={tb}")
            err = f"{exc}\ntrace={tb}"
            return {"transactions": [], "meta": anchor_open.get("meta"), "canSend": False, "notes": notes, "error": err}

    # ---------------- Liquidez CLMM: Send ----------------
    def liquidity_send(self, prep: Dict[str, Any], wait: bool = True) -> Dict[str, Any]:
        """Firma y envía las transacciones V0 devueltas por liquidity_prepare.
        Reutiliza el flujo de swap_send (firmado y confirmación) con las tx base64.
        """
        if not isinstance(prep, dict):
            return {"error": "prep inválido"}
        txs = prep.get("transactions")
        if not isinstance(txs, list) or not all(isinstance(x, str) for x in txs):
            return {"error": "prep.transactions inválido"}
        # Reusar pipeline de swap_send: acepta {transactions: [...]} ya en base64
        try:
            # Pasar prep completo para soportar extraSigners en flujo Anchor
            res = self.swap_send(prep, wait=wait)
            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info("clmm_send: signatures=%s", (res.get("signatures") if isinstance(res, dict) else None))
            # Extraer NFT/ids desde receipts (getTransaction por firma)
            try:
                sigs = (res.get("signatures") if isinstance(res, dict) else None) or []
                all_nfts: List[str] = []
                all_pdas: List[str] = []
                for sig in sigs:
                    txr = self._get_transaction_parsed(sig)
                    if not txr:
                        continue
                    ext = self._extract_position_nfts_from_tx(txr)
                    for m in ext.get("nfts", []):
                        if m not in all_nfts:
                            all_nfts.append(m)
                    for p in ext.get("pdas", []):
                        if p not in all_pdas:
                            all_pdas.append(p)
                # Fallback: si no se detecta NFT en receipts y venimos de Anchor, usar mint previsto
                if not all_nfts:
                    try:
                        ix = ((prep or {}).get("anchor") or {}).get("ix") or {}
                        pos = (ix.get("accounts") or {}).get("positionNft") or {}
                        mint_planned = pos.get("mint")
                        if isinstance(mint_planned, str) and mint_planned:
                            all_nfts = [mint_planned]
                            # Derivar PDA de posición personal para reportar
                            try:
                                pda, _b = self._derive_personal_position_pda(mint_planned)
                                if pda:
                                    all_pdas = [pda]
                            except Exception:
                                pass
                    except Exception:
                        pass
                if isinstance(res, dict):
                    res["position"] = {"nftMints": (all_nfts or None), "pdas": (all_pdas or None)}
            except Exception:
                pass
            return res
        except Exception as exc:
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning("clmm_send failed: %s", exc)
            return {"error": str(exc)}

    # ---------------- Raydium Trade API: Quote ----------------
    def get_quote(self, input_mint: str, output_mint: str, amount: int, kind: str, slippage_bps: int) -> Dict[str, Any]:
        if kind not in ("exact_in", "exact_out"):
            raise ValueError("kind debe ser 'exact_in' o 'exact_out'")
        if not input_mint or not output_mint:
            raise ValueError("input_mint y output_mint son obligatorios")
        if int(amount) <= 0:
            raise ValueError("amount debe ser > 0 (en unidades mínimas)")
        if not (0 < int(slippage_bps) <= 10_000):
            raise ValueError("slippage_bps fuera de rango (1..10000)")
        # Autodetectar wrap/unwrap según mints
        wrap_sol = (input_mint == self.SOL_MINT)
        unwrap_sol = (output_mint == self.SOL_MINT)
        path = "compute/swap-base-in" if kind == "exact_in" else "compute/swap-base-out"
        params = {
            "inputMint": input_mint,
            "outputMint": output_mint,
            "amount": str(int(amount)),
            "slippageBps": int(slippage_bps),
            "txVersion": "V0",
        }
        data = self._api_get(path, params=params)
        if isinstance(data, dict) and data.get("success") is False and data.get("message"):
            raise RuntimeError(f"Raydium compute error: {data.get('message')}")
        # La API devuelve un objeto complejo; encapsulamos lo esencial y guardamos swapResponse completo
        return {
            "swapResponse": data,
            "kind": kind,
            "inputMint": input_mint,
            "outputMint": output_mint,
            "amount": int(amount),
            "slippageBps": int(slippage_bps),
            "wrapSol": bool(wrap_sol),
            "unwrapSol": bool(unwrap_sol),
        }

    # ---------------- Raydium Trade API: Prepare ----------------
    def _derive_ata(self, owner_pubkey: str, mint: str, token_program_id: Optional[str] = None) -> Optional[str]:
        """Deriva Associated Token Account (ATA) para (owner,mint).
        Para Token-2022, pasar token_program_id="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".
        """
        try:
            from solders.pubkey import Pubkey  # type: ignore
        except Exception as exc:
            self.logger.warning("solders no disponible para derivar ATA: %s", exc)
            return None
        try:
            TOKEN_PROGRAM_ID = Pubkey.from_string(token_program_id or "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            ATA_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
            owner_pk = Pubkey.from_string(owner_pubkey)
            mint_pk = Pubkey.from_string(mint)
            seeds = [bytes(owner_pk), bytes(TOKEN_PROGRAM_ID), bytes(mint_pk)]
            ata, _bump = Pubkey.find_program_address(seeds, ATA_PROGRAM_ID)
            return str(ata)
        except Exception as exc:
            self.logger.warning("Error derivando ATA: %s", exc)
            return None

    def swap_prepare(self, swap_quote: Dict[str, Any]) -> Dict[str, Any]:
        kind = swap_quote.get("kind")
        if kind not in ("exact_in", "exact_out"):
            raise ValueError("swap_quote.kind inválido")
        # Obtener prioridad
        priority = self._get_priority_fee_micro_lamports()
        if priority is None:
            # fallback conservador si la API no devuelve datos
            priority = {"vh": 1_000_000, "h": 500_000, "m": 200_000}.get(self.config.priority_fee_tier, 500_000)
        payload = {
            "computeUnitPriceMicroLamports": str(priority) if priority is not None else None,
            "swapResponse": swap_quote.get("swapResponse"),
            "txVersion": "V0",
            "wallet": self.owner_pubkey,
        }
        # wrap/unwrap SOL
        wrap_sol = bool(swap_quote.get("wrapSol"))
        unwrap_sol = bool(swap_quote.get("unwrapSol"))
        if wrap_sol:
            payload["wrapSol"] = True
        if unwrap_sol:
            payload["unwrapSol"] = True
        # input/output accounts
        input_mint = swap_quote.get("inputMint")
        output_mint = swap_quote.get("outputMint")
        if input_mint and input_mint != self.SOL_MINT:  # no SOL nativo
            ata_in = self._derive_ata(self.owner_pubkey, input_mint)
            if ata_in:
                payload["inputAccount"] = ata_in
        if output_mint and output_mint == self.SOL_MINT:
            # si se desea SOL nativo, la API soporta unwrapSol
            payload["unwrapSol"] = True

        path = "transaction/swap-base-in" if kind == "exact_in" else "transaction/swap-base-out"
        res = self._api_post(path, payload)
        if isinstance(res, dict) and res.get("success") is False and res.get("message"):
            raise RuntimeError(f"Raydium transaction error: {res.get('message')}")
        # Extraer transacciones de forma robusta (puede venir list o dict)
        transactions: List[str] = []
        items: List[Any] = []
        if isinstance(res, list):
            items = res
        elif isinstance(res, dict):
            data_field = res.get("data")
            if isinstance(data_field, list):
                items = data_field
            elif isinstance(data_field, dict):
                items = [data_field]
            else:
                # a veces la tx está directamente en res
                items = [res]
        for it in items:
            if isinstance(it, dict) and isinstance(it.get("transaction"), str):
                transactions.append(it["transaction"])
        if not transactions:
            raise RuntimeError("Raydium API no devolvió transacciones a firmar")
        return {
            "transactions": transactions,
            "txVersion": "V0",
        }

    # ---------------- Raydium Trade API: Send ----------------
    def _load_solana_keypair(self):
        try:
            from solders.keypair import Keypair  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Falta dependencia solders: {exc}")
        expanded_path = os.path.expanduser(self.config.keypair_path)
        with open(expanded_path, "r", encoding="utf-8") as f:
            key_data = json.load(f)
        secret = bytes(key_data)
        # Formato estándar Solana: 64 bytes (priv||pub)
        if len(secret) == 64:
            return Keypair.from_bytes(secret)
        # Si viniera 32 bytes, usar como seed
        seed = secret[:32]
        return Keypair.from_seed(seed)

    def _rpc_client(self):
        try:
            from solana.rpc.api import Client  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Falta dependencia solana-py: {exc}")
        return Client(self.rpc.current)

    def _get_latest_blockhash(self) -> str:
        import requests
        data = self._rpc_call_with_failover("getLatestBlockhash", [{"commitment": "finalized"}])
        result = data.get("result") or {}
        value = result.get("value") or {}
        bh = value.get("blockhash")
        if not isinstance(bh, str):
            raise RuntimeError("No se pudo obtener latest blockhash")
        return bh

    def _get_token_account_balance_int(self, token_account: str) -> Optional[int]:
        """Devuelve el balance (amount entero, sin decimales) de una cuenta SPL usando getTokenAccountBalance.
        Retorna None si no está disponible.
        """
        try:
            resp = self._rpc_call_with_failover("getTokenAccountBalance", [token_account, {"commitment": "finalized"}])
            val = (resp.get("result") or {}).get("value") or {}
            amt = val.get("amount")
            if isinstance(amt, str) and amt.isdigit():
                return int(amt)
            try:
                return int(str(amt))
            except Exception:
                return None
        except Exception:
            return None

    def _get_native_sol_balance_int(self) -> Optional[int]:
        """Devuelve balance nativo de SOL (lamports) del owner con getBalance."""
        try:
            resp = self._rpc_call_with_failover("getBalance", [self.owner_pubkey, {"commitment": "finalized"}])
            val = (resp.get("result") or {})
            lamports = val.get("value")
            if isinstance(lamports, int):
                return lamports
            try:
                return int(str(lamports))
            except Exception:
                return None
        except Exception:
            return None

    def _get_token_balance_sum_by_mint(self, mint: str) -> int:
        """Suma el balance de todos los token accounts del owner para un mint dado (u64 en unidades mínimas)."""
        import requests
        if not isinstance(mint, str):
            return 0
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getParsedTokenAccountsByOwner",
                "params": [
                    self.owner_pubkey,
                    {"mint": mint},
                    {"commitment": "finalized"},
                ],
            }
            resp = requests.post(self.rpc.current, json=payload, timeout=12)
            resp.raise_for_status()
            data = resp.json() or {}
            result = (data.get("result") or {})
            value = result.get("value") or []
            total = 0
            for it in value:
                try:
                    acc = (it or {}).get("account") or {}
                    parsed = (acc.get("data") or {}).get("parsed") or {}
                    info = parsed.get("info") or {}
                    ui = (info.get("tokenAmount") or info.get("tokenAmount")) or {}
                    amount = ui.get("amount")
                    if isinstance(amount, str) and amount.isdigit():
                        total += int(amount)
                    else:
                        try:
                            total += int(str(amount))
                        except Exception:
                            continue
                except Exception:
                    continue
            return int(total)
        except Exception:
            # Intento alternativo con rotación simple del endpoint
            try:
                _ = self.rpc.rotate()
            except Exception:
                pass
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getParsedTokenAccountsByOwner",
                    "params": [
                        self.owner_pubkey,
                        {"mint": mint},
                        {"commitment": "finalized"},
                    ],
                }
                import requests as _rq
                r2 = _rq.post(self.rpc.current, json=payload, timeout=12)
                r2.raise_for_status()
                d2 = r2.json() or {}
                res2 = (d2.get("result") or {})
                val2 = res2.get("value") or []
                tot = 0
                for it in val2:
                    try:
                        acc = (it or {}).get("account") or {}
                        parsed = (acc.get("data") or {}).get("parsed") or {}
                        info = parsed.get("info") or {}
                        ui = (info.get("tokenAmount") or info.get("tokenAmount")) or {}
                        amount = ui.get("amount")
                        if isinstance(amount, str) and amount.isdigit():
                            tot += int(amount)
                        else:
                            try:
                                tot += int(str(amount))
                            except Exception:
                                continue
                    except Exception:
                        continue
                return int(tot)
            except Exception:
                return 0

    def wallet_state(self) -> dict:
        """Estado de wallet: SOL nativo y balances por mint conocidos (derivables del contexto de pools).
        No usa fallbacks excepto rotación de endpoint RPC.
        """
        state: Dict[str, Any] = {"owner": self.owner_pubkey, "native": {}, "balances": {}, "atas": {}}
        sol = self._get_native_sol_balance_int() or 0
        state["native"]["SOL"] = int(sol)

        def _collect_by_program(program_id: str) -> None:
            try:
                # Usar getTokenAccountsByOwner con encoding jsonParsed para máxima compatibilidad
                resp = self._rpc_call_with_failover(
                    "getTokenAccountsByOwner",
                    [
                        self.owner_pubkey,
                        {"programId": program_id},
                        {"commitment": "finalized", "encoding": "jsonParsed"},
                    ],
                )
                value = ((resp or {}).get("result") or {}).get("value") or []
                for it in value:
                    try:
                        pubkey = it.get("pubkey")
                        acc = (it.get("account") or {})
                        parsed = ((acc.get("data") or {}).get("parsed") or {})
                        info = parsed.get("info") or {}
                        mint = info.get("mint")
                        ta = info.get("tokenAmount") or {}
                        amount = ta.get("amount")
                        decimals = ta.get("decimals")
                        ui = ta.get("uiAmountString")
                        if not isinstance(mint, str):
                            continue
                        # ATAs por mint
                        state["atas"].setdefault(mint, [])
                        if isinstance(pubkey, str):
                            state["atas"][mint].append(pubkey)
                        # Acumulado de amount entero
                        try:
                            amt_i = int(amount) if isinstance(amount, str) else int(str(amount))
                        except Exception:
                            continue
                        entry = state["balances"].setdefault(mint, {"amount": 0, "decimals": decimals, "ui": ui})
                        entry["amount"] = int(entry.get("amount", 0)) + int(amt_i)
                        # Mantener el mayor "decimals" conocido y una ui representativa si no existe
                        if isinstance(decimals, int):
                            prev_dec = entry.get("decimals")
                            if not isinstance(prev_dec, int):
                                entry["decimals"] = decimals
                        if ui and not entry.get("ui"):
                            entry["ui"] = ui
                    except Exception:
                        continue
            except Exception:
                return

        # Token Program (SPL) y Token-2022
        _collect_by_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        _collect_by_program("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")

        # Filtrar balances en cero y sincronizar ATAs
        try:
            balances = state.get("balances") or {}
            filtered = {mint: info for mint, info in balances.items() if int((info or {}).get("amount", 0)) > 0}
            state["balances"] = filtered
            atas = state.get("atas") or {}
            if isinstance(atas, dict):
                state["atas"] = {mint: atas.get(mint, []) for mint in filtered.keys()}
        except Exception:
            pass

        return state

    def _assemble_v0_from_anchor(self, anchor_obj: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Empaqueta ComputeBudget + ix Anchor en una transacción V0 y la devuelve en base64.
        Retorna (tx_b64, extra_signers_b64[]).
        """
        try:
            from solders.instruction import Instruction as SInstruction, AccountMeta  # type: ignore
            from solders.message import MessageV0  # type: ignore
            from solders.transaction import VersionedTransaction  # type: ignore
            from solders.pubkey import Pubkey  # type: ignore
            from solders.keypair import Keypair  # type: ignore
            from solders.compute_budget import (  # type: ignore
                set_compute_unit_price, set_compute_unit_limit,
            )
            from solders.hash import Hash as SolHash  # type: ignore
            from solders.signature import Signature as SolSig  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Faltan dependencias solders para ensamblar V0: {exc}")

        anc = anchor_obj or {}
        ix_desc = (anc.get("anchor") or {}).get("ix") or {}
        cb = (anc.get("anchor") or {}).get("computeBudget") or {}
        prewrap = (anc.get("anchor") or {}).get("prewrap") or []
        postunwrap = (anc.get("anchor") or {}).get("postunwrap") or []
        create_atas = (anc.get("anchor") or {}).get("createATAs") or []
        create_with_seed = (anc.get("anchor") or {}).get("createWithSeed") or []
        extra_anchor_ixs = (anc.get("anchor") or {}).get("extraIxs") or []  # lista de ixs extra tipo Anchor
        # Autorrellenar prewrap si falta pero hay SOL en el par (basado en token_accounts y/o decodificando ix.data)
        try:
            if not prewrap:
                meta = anc.get("meta") or {}
                accs = (ix_desc.get("accounts") or {}) if isinstance(ix_desc, dict) else {}
                token_accs = (accs.get("tokenAccounts") or {})
                ta0 = token_accs.get("A") or ix_desc.get("token_account_0")
                ta1 = token_accs.get("B") or ix_desc.get("token_account_1")
                amounts = meta.get("amounts") or {}
                expected_wsol_ata = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
                if isinstance(expected_wsol_ata, str):
                    # Intento 1: usar meta (si existe)
                    if isinstance(ta0, str) and ta0 == expected_wsol_ata and isinstance(amounts.get("A"), int) and int(amounts.get("A", 0)) > 0:
                        prewrap = [{"kind": "wrap", "mint": self.SOL_MINT, "ata": ta0, "lamports": int(amounts.get("A", 0))}]
                        postunwrap = postunwrap or [{"kind": "unwrap", "ata": ta0}]
                    elif isinstance(ta1, str) and ta1 == expected_wsol_ata and isinstance(amounts.get("B"), int) and int(amounts.get("B", 0)) > 0:
                        prewrap = [{"kind": "wrap", "mint": self.SOL_MINT, "ata": ta1, "lamports": int(amounts.get("B", 0))}]
                        postunwrap = postunwrap or [{"kind": "unwrap", "ata": ta1}]
                    else:
                        # Intento 2: decodificar amounts desde ix.data (Anchor: discr(8) + i32*4 + u128 + u64(amount0) + u64(amount1) ...)
                        try:
                            data_b = ix_desc.get("data") if isinstance(ix_desc, dict) else None
                            # Normalizar a bytes para poder decodificar amounts desde el payload Anchor
                            if isinstance(data_b, list):
                                try:
                                    buf = bytearray()
                                    for x in data_b:
                                        if isinstance(x, int):
                                            buf.append(x & 0xFF)
                                        elif isinstance(x, (bytes, bytearray)):
                                            buf.extend(x)
                                        elif isinstance(x, str):
                                            s = x.strip()
                                            if s.startswith("0x"):
                                                try:
                                                    buf.extend(bytes.fromhex(s[2:]))
                                                except Exception:
                                                    buf.extend(s.encode("utf-8"))
                                            else:
                                                # intentar base64; si falla, utf-8
                                                import base64 as _b64
                                                try:
                                                    buf.extend(_b64.b64decode(s))
                                                except Exception:
                                                    buf.extend(s.encode("utf-8"))
                                        else:
                                            buf.extend(bytes(str(x), "utf-8"))
                                    data_b = bytes(buf)
                                except Exception:
                                    data_b = None
                            elif isinstance(data_b, str):
                                s = data_b.strip()
                                if s.startswith("0x"):
                                    try:
                                        data_b = bytes.fromhex(s[2:])
                                    except Exception:
                                        data_b = s.encode("utf-8")
                                else:
                                    import base64 as _b64
                                    try:
                                        data_b = _b64.b64decode(s)
                                    except Exception:
                                        data_b = s.encode("utf-8")
                            elif isinstance(data_b, memoryview):
                                data_b = bytes(data_b)

                            if isinstance(data_b, (bytes, bytearray)) and len(data_b) >= 56:
                                amt0_le = int.from_bytes(bytes(data_b[40:48]), byteorder="little", signed=False)
                                amt1_le = int.from_bytes(bytes(data_b[48:56]), byteorder="little", signed=False)
                                if isinstance(ta0, str) and ta0 == expected_wsol_ata and amt0_le > 0:
                                    prewrap = [{"kind": "wrap", "mint": self.SOL_MINT, "ata": ta0, "lamports": int(amt0_le)}]
                                    postunwrap = postunwrap or [{"kind": "unwrap", "ata": ta0}]
                                elif isinstance(ta1, str) and ta1 == expected_wsol_ata and amt1_le > 0:
                                    prewrap = [{"kind": "wrap", "mint": self.SOL_MINT, "ata": ta1, "lamports": int(amt1_le)}]
                                    postunwrap = postunwrap or [{"kind": "unwrap", "ata": ta1}]
                        except Exception:
                            pass
        except Exception:
            pass
        # Reconciliar SIEMPRE el prewrap con el ATA WSOL y los amounts del payload Anchor
        try:
            meta = anc.get("meta") or {}
            accs = (ix_desc.get("accounts") or {}) if isinstance(ix_desc, dict) else {}
            token_accs = (accs.get("tokenAccounts") or {})
            ta0 = token_accs.get("A") or ix_desc.get("token_account_0")
            ta1 = token_accs.get("B") or ix_desc.get("token_account_1")
            expected_wsol_ata = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
            # Decodificar amounts desde ix.data si es necesario
            data_b2 = ix_desc.get("data") if isinstance(ix_desc, dict) else None
            if isinstance(data_b2, list):
                try:
                    buf = bytearray()
                    for x in data_b2:
                        if isinstance(x, int):
                            buf.append(x & 0xFF)
                        elif isinstance(x, (bytes, bytearray)):
                            buf.extend(x)
                        elif isinstance(x, str):
                            s = x.strip()
                            if s.startswith("0x"):
                                try:
                                    buf.extend(bytes.fromhex(s[2:]))
                                except Exception:
                                    buf.extend(s.encode("utf-8"))
                            else:
                                import base64 as _b64
                                try:
                                    buf.extend(_b64.b64decode(s))
                                except Exception:
                                    buf.extend(s.encode("utf-8"))
                        else:
                            buf.extend(bytes(str(x), "utf-8"))
                    data_b2 = bytes(buf)
                except Exception:
                    data_b2 = None
            elif isinstance(data_b2, str):
                s = data_b2.strip()
                if s.startswith("0x"):
                    try:
                        data_b2 = bytes.fromhex(s[2:])
                    except Exception:
                        data_b2 = s.encode("utf-8")
                else:
                    import base64 as _b64
                    try:
                        data_b2 = _b64.b64decode(s)
                    except Exception:
                        data_b2 = s.encode("utf-8")
            elif isinstance(data_b2, memoryview):
                data_b2 = bytes(data_b2)
            amt0_from_ix = None
            amt1_from_ix = None
            if isinstance(data_b2, (bytes, bytearray)) and len(data_b2) >= 56:
                try:
                    amt0_from_ix = int.from_bytes(bytes(data_b2[40:48]), byteorder="little", signed=False)
                    amt1_from_ix = int.from_bytes(bytes(data_b2[48:56]), byteorder="little", signed=False)
                except Exception:
                    amt0_from_ix = None
                    amt1_from_ix = None
            def _ensure_prewrap_for(ata: Optional[str], amt: Optional[int]):
                if not isinstance(ata, str) or ata != expected_wsol_ata or not isinstance(amt, int) or amt <= 0:
                    return
                # Buscar entrada existente y ajustarla
                found = False
                for w in prewrap:
                    if isinstance(w, dict) and w.get("ata") == ata:
                        found = True
                        cur = int(w.get("lamports", 0))
                        if amt > cur:
                            w["lamports"] = int(amt)
                        break
                if not found:
                    prewrap.append({"kind": "wrap", "mint": self.SOL_MINT, "ata": ata, "lamports": int(amt)})
            if isinstance(expected_wsol_ata, str):
                _ensure_prewrap_for(ta0, amt0_from_ix)
                _ensure_prewrap_for(ta1, amt1_from_ix)
            # Garantizar postunwrap si hay prewrap WSOL y falta
            if prewrap and not postunwrap:
                try:
                    # usar el primer ATA WSOL como destino de closeAccount
                    for w in prewrap:
                        if isinstance(w, dict) and w.get("mint") == self.SOL_MINT and isinstance(w.get("ata"), str):
                            postunwrap = [{"kind": "unwrap", "ata": w.get("ata") }]
                            break
                except Exception:
                    pass
            if self.logger.isEnabledFor(logging.INFO):
                try:
                    self.logger.info("assemble_v0: prewrap reconciled count=%d", len(prewrap))
                except Exception:
                    pass
        except Exception:
            pass
        prog_id = ix_desc.get("program_id")
        keys_desc = ix_desc.get("keys", [])
        data_bytes = ix_desc.get("data", b"")
        # Normalizar data a bytes
        if isinstance(data_bytes, list):
            try:
                buf = bytearray()
                for x in data_bytes:
                    if isinstance(x, int):
                        buf.append(x & 0xFF)
                    elif isinstance(x, (bytes, bytearray)):
                        buf.extend(x)
                    elif isinstance(x, str):
                        s = x.strip()
                        if s.startswith("0x"):
                            buf.extend(bytes.fromhex(s[2:]))
                        else:
                            buf.extend(s.encode("utf-8"))
                    else:
                        # último recurso: to-string y utf8
                        try:
                            buf.extend(str(x).encode("utf-8"))
                        except Exception:
                            pass
                data_bytes = bytes(buf)
            except Exception:
                raise RuntimeError("anchor ix data inválido: no convertible a bytes (list)")
        elif isinstance(data_bytes, bytearray):
            data_bytes = bytes(data_bytes)
        elif isinstance(data_bytes, memoryview):
            data_bytes = bytes(data_bytes)
        elif isinstance(data_bytes, str):
            # Posibles formatos: "b'..'", hex "0x.." o texto binario; intentos seguros
            s = data_bytes.strip()
            if s.startswith("0x"):
                try:
                    data_bytes = bytes.fromhex(s[2:])
                except Exception:
                    data_bytes = s.encode("utf-8")
            elif s.startswith("b'") or s.startswith('b"'):
                try:
                    data_bytes = eval(s)  # bytes literal; controlado por nuestro código
                    if not isinstance(data_bytes, (bytes, bytearray)):
                        data_bytes = str(s).encode("utf-8")
                except Exception:
                    data_bytes = s.encode("utf-8")
            else:
                data_bytes = s.encode("utf-8")

        # Debug: tipo/tamaño de data antes de construir la instrucción
        if self.logger.isEnabledFor(logging.INFO):
            try:
                sample = None
                if isinstance(data_bytes, (bytes, bytearray)):
                    sample = list(data_bytes[:16])
                self.logger.info("assemble_v0: anchor_ix.data type=%s len=%s sample=%s",
                                 type(data_bytes).__name__, (len(data_bytes) if hasattr(data_bytes, "__len__") else None), sample)
            except Exception:
                pass
        if not isinstance(prog_id, str) or not keys_desc or not isinstance(data_bytes, (bytes, bytearray)):
            raise RuntimeError("anchor ix inválida para ensamblar")

        # Compute budget Ixs (helpers + reconstrucción para asegurar bytes)
        cu_price = int(cb.get("microLamports", 25_000))
        cu_limit = int(cb.get("units", 600_000))
        ix_cu_price = None
        ix_cu_limit = None
        try:
            ix_cu_price_h = set_compute_unit_price(cu_price)
            ix_cu_limit_h = set_compute_unit_limit(cu_limit)
            ix_cu_price = SInstruction(ix_cu_price_h.program_id, bytes(ix_cu_price_h.data), tuple(ix_cu_price_h.accounts))
            ix_cu_limit = SInstruction(ix_cu_limit_h.program_id, bytes(ix_cu_limit_h.data), tuple(ix_cu_limit_h.accounts))
            if self.logger.isEnabledFor(logging.INFO):
                try:
                    self.logger.info("assemble_v0: compute helpers OK (price_type=%s, limit_type=%s)", type(ix_cu_price_h.data).__name__, type(ix_cu_limit_h.data).__name__)
                except Exception:
                    pass
        except Exception as exc_cb2:
            # Fallback manual si los helpers no están disponibles
            cb_pid = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
            data_limit_raw = bytes([2]) + int(cu_limit).to_bytes(4, "little", signed=False)
            data_price_raw = bytes([3]) + int(cu_price).to_bytes(8, "little", signed=False)
            # Normalización estricta y diagnóstico
            def _force_bytes(x: Any) -> bytes:
                if isinstance(x, (bytes, bytearray)):
                    return bytes(x)
                if isinstance(x, list):
                    return bytes(bytearray((int(v) & 0xFF) for v in x))
                if isinstance(x, memoryview):
                    return bytes(x)
                if isinstance(x, int):
                    return bytes([x & 0xFF])
                try:
                    return bytes(x)
                except Exception:
                    return bytes(str(x), "utf-8")
            data_limit_b = _force_bytes(data_limit_raw)
            data_price_b = _force_bytes(data_price_raw)
            if self.logger.isEnabledFor(logging.INFO):
                try:
                    self.logger.info("assemble_v0: cb manual types (limit=%s, price=%s) lens=(%s,%s)", type(data_limit_b).__name__, type(data_price_b).__name__, len(data_limit_b), len(data_price_b))
                except Exception:
                    pass
            try:
                ix_cu_limit = SInstruction(cb_pid, data_limit_b, tuple(()))
                ix_cu_price = SInstruction(cb_pid, data_price_b, tuple(()))
            except Exception as exc_manual:
                if self.logger.isEnabledFor(logging.ERROR):
                    try:
                        self.logger.error("assemble_v0: compute manual build failed: %s (limit_len=%s price_len=%s)", exc_manual, len(data_limit_b), len(data_price_b))
                    except Exception:
                        pass
                ix_cu_limit = None
                ix_cu_price = None
            if self.logger.isEnabledFor(logging.WARNING):
                try:
                    self.logger.warning(
                        "assemble_v0: compute helpers fallback: price_len=%s limit_len=%s",
                        len(data_price_b), len(data_limit_b)
                    )
                except Exception:
                    pass
        if self.logger.isEnabledFor(logging.INFO):
            try:
                self.logger.info("assemble_v0: compute budget ixs listos (price=%d, limit=%d) present=(%s,%s)", cu_price, cu_limit, bool(ix_cu_price), bool(ix_cu_limit))
            except Exception:
                pass

        # Anchor ix principal
        def to_meta(k: Dict[str, Any]) -> AccountMeta:
            pk = Pubkey.from_string(k.get("pubkey"))
            return AccountMeta(pk, bool(k.get("is_signer")), bool(k.get("is_writable")))
        metas = [to_meta(k) for k in keys_desc if isinstance(k, dict) and k.get("pubkey")]
        program_pk = Pubkey.from_string(prog_id)
        try:
            anchor_ix = SInstruction(program_pk, bytes(data_bytes), tuple(metas))
        except Exception as exc_ix:
            try:
                meta_dump = [{"pubkey": str(m.pubkey), "is_signer": m.is_signer, "is_writable": m.is_writable} for m in metas]
                self.logger.error("assemble_v0: fallo creando anchor_ix: %s | program=%s data_type=%s data_len=%s metas=%s",
                                  exc_ix,
                                  str(program_pk),
                                  type(data_bytes).__name__,
                                  (len(data_bytes) if hasattr(data_bytes, "__len__") else None),
                                  meta_dump)
            except Exception:
                pass
            raise
        if self.logger.isEnabledFor(logging.INFO):
            try:
                self.logger.info("assemble_v0: anchor_ix creado OK (program=%s data_len=%s)", str(program_pk), len(bytes(data_bytes)))
            except Exception:
                pass

        # Ensamblar mensaje V0
        recent_blockhash = self._get_latest_blockhash()
        payer_pk = Pubkey.from_string(self.owner_pubkey)
        # Build create ATA + createWithSeed + wrap/unwrap ixs usando ATA, Token y System Program
        sys_program = Pubkey.from_string("11111111111111111111111111111111")
        token_program = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        wsol_mint = Pubkey.from_string(self.SOL_MINT)
        ata_program = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
        wrap_ixs: List[Any] = []
        # 0) Create ATAs que falten
        def _try_build_create_ata(owner_str: str, mint_str: str) -> Optional[Any]:
            # Construir manualmente la ix de creación de ATA (datos vacíos)
            try:
                owner_pk = Pubkey.from_string(owner_str)
                mint_pk = Pubkey.from_string(mint_str)
                ata_str = self._derive_ata(owner_str, mint_str)
                if not ata_str:
                    return None
                ata_pk = Pubkey.from_string(ata_str)
                rent_pk = Pubkey.from_string("SysvarRent111111111111111111111111111111111")
                metas = [
                    AccountMeta(payer_pk, True, True),        # payer (signer, writable)
                    AccountMeta(ata_pk, False, True),         # associated token account (writable)
                    AccountMeta(owner_pk, False, False),      # owner
                    AccountMeta(mint_pk, False, False),       # mint
                    AccountMeta(sys_program, False, False),   # system program
                    AccountMeta(token_program, False, False), # token program
                    AccountMeta(rent_pk, False, False),       # rent sysvar
                ]
                return SInstruction(ata_program, b"", tuple(metas))
            except Exception:
                return None
        for ca in create_atas:
            try:
                owner_str = ca.get("owner")
                mint_str = ca.get("mint")
                ix = _try_build_create_ata(owner_str, mint_str)
                if ix:
                    wrap_ixs.append(ix)
                    if self.logger.isEnabledFor(logging.INFO):
                        try:
                            data = getattr(ix, "data", None)
                            self.logger.info("assemble_v0: create_ata ix añadido (owner=%s mint=%s) data_type=%s", owner_str, mint_str, (type(data).__name__ if data is not None else None))
                        except Exception:
                            pass
            except Exception:
                continue
        # 0.b) CreateAccountWithSeed + InitializeAccount (para cuenta WSOL temporal)
        for cws in (create_with_seed or []):
            try:
                base_str = str(cws.get("base"))
                seed_str = str(cws.get("seed"))
                new_acc_str = str(cws.get("newAccount"))
                lamports = int(cws.get("lamports", 0))
                # Intento 1: helper solders
                ix_seed = None
                try:
                    from solders.system_program import create_account_with_seed, CreateAccountWithSeedParams  # type: ignore
                    base_pk = Pubkey.from_string(base_str)
                    new_pk = Pubkey.from_string(new_acc_str)
                    ix_seed = create_account_with_seed(CreateAccountWithSeedParams(
                        from_pubkey=payer_pk,
                        new_account_pubkey=new_pk,
                        base=base_pk,
                        seed=seed_str,
                        lamports=lamports,
                        space=165,
                        owner=token_program,
                    ))
                    wrap_ixs.append(ix_seed)
                except Exception:
                    # Intento 2: construir manualmente la ix (SystemProgram::CreateAccountWithSeed)
                    try:
                        sys_program = Pubkey.from_string("11111111111111111111111111111111")
                        base_pk = Pubkey.from_string(base_str)
                        new_pk = Pubkey.from_string(new_acc_str)
                        import struct as _st
                        # borsh: u32 instr(3), base(32), seed(str: u32 len + bytes), lamports(u64), space(u64), owner(32)
                        data_buf = bytearray()
                        data_buf += (3).to_bytes(4, "little", signed=False)
                        data_buf += bytes(base_pk)
                        seed_bytes = seed_str.encode("utf-8")
                        # bincode for SystemInstruction uses u64 for string len
                        data_buf += len(seed_bytes).to_bytes(8, "little", signed=False)
                        data_buf += seed_bytes
                        data_buf += int(lamports).to_bytes(8, "little", signed=False)
                        data_buf += int(165).to_bytes(8, "little", signed=False)
                        data_buf += bytes(token_program)
                        metas_seed = [
                            AccountMeta(payer_pk, True, True),
                            AccountMeta(new_pk, False, True),
                            AccountMeta(base_pk, False, False),
                        ]
                        ix_seed = SInstruction(sys_program, bytes(data_buf), tuple(metas_seed))
                        wrap_ixs.append(ix_seed)
                    except Exception:
                        ix_seed = None
                # initializeAccount (Token Program v2): tag=1, cuentas: [account(w), mint(r), owner(r), rent]
                rent_pk = Pubkey.from_string("SysvarRent111111111111111111111111111111111")
                metas_init = [
                    AccountMeta(new_pk, False, True),
                    AccountMeta(wsol_mint, False, False),
                    AccountMeta(payer_pk, False, False),
                    AccountMeta(rent_pk, False, False),
                ]
                init_ix = SInstruction(token_program, bytes([1]), tuple(metas_init))
                wrap_ixs.append(init_ix)
            except Exception:
                continue
        # 0.b-extra) Salvaguarda: si el ix anchor usa una cuenta WSOL temporal derivable y aún no hemos añadido create+init, crearla aquí
        try:
            # Detectar si el ix corresponde a decrease_liquidity_v2 y extraer recipient_token_account_0
            keys_for_ix = list(keys_desc) if isinstance(keys_desc, list) else []
            looks_like_dec = (
                isinstance(prog_id, str)
                and str(prog_id) == str(self.config.program_id_clmm)
                and len(keys_for_ix) >= 15
            )
            if looks_like_dec:
                recv0_key = None
                try:
                    recv0_key = keys_for_ix[9].get("pubkey") if isinstance(keys_for_ix[9], dict) else None
                except Exception:
                    recv0_key = None
                # Extraer position nft mint del objeto de cuentas si está disponible
                accs_map = (ix_desc.get("accounts") or {}) if isinstance(ix_desc, dict) else {}
                pos_mint = accs_map.get("positionNftMint")
                # expected ATA WSOL del owner
                expected_wsol_ata = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
                # Función para comprobar si ya añadimos create/init para recv0_key
                def _has_seed_setup_for(target_pk: str) -> bool:
                    has_create = False
                    has_init = False
                    for ix in wrap_ixs:
                        try:
                            pid = getattr(ix, "program_id", None)
                            if pid is None:
                                continue
                            if str(pid) == str(sys_program):
                                # create_with_seed incluye la cuenta nueva como writable
                                for am in list(getattr(ix, "accounts", []) or []):
                                    try:
                                        if str(getattr(am, "pubkey", "")) == target_pk and bool(getattr(am, "is_writable", False)):
                                            has_create = True
                                            break
                                    except Exception:
                                        continue
                            if str(pid) == str(token_program):
                                data = getattr(ix, "data", b"")
                                tag = None
                                try:
                                    tag = int(data[0]) if isinstance(data, (bytes, bytearray)) and len(data) > 0 else None
                                except Exception:
                                    tag = None
                                if tag == 1:
                                    # initializeAccount: primera cuenta debe ser la nueva
                                    accts = list(getattr(ix, "accounts", []) or [])
                                    if accts and str(getattr(accts[0], "pubkey", "")) == target_pk:
                                        has_init = True
                        except Exception:
                            continue
                    return has_create and has_init
                if (
                    isinstance(recv0_key, str)
                    and recv0_key
                    and recv0_key != expected_wsol_ata
                    and isinstance(pos_mint, str)
                    and len(pos_mint) > 0
                    and not _has_seed_setup_for(recv0_key)
                ):
                    # Recrear la misma dirección con seed determinista y verificar coincidencia
                    import hashlib as _hl
                    seed_str = _hl.sha256((pos_mint + ":wsol").encode("utf-8")).hexdigest()[:32]
                    try:
                        derived = Pubkey.create_with_seed(payer_pk, seed_str, token_program)
                        if str(derived) == recv0_key:
                            from solders.system_program import create_account_with_seed, CreateAccountWithSeedParams  # type: ignore
                            lamports = 2_039_280
                            ix_seed = create_account_with_seed(CreateAccountWithSeedParams(
                                from_pubkey=payer_pk,
                                new_account_pubkey=derived,
                                base=payer_pk,
                                seed=seed_str,
                                lamports=lamports,
                                space=165,
                                owner=token_program,
                            ))
                            wrap_ixs.append(ix_seed)
                            rent_pk = Pubkey.from_string("SysvarRent111111111111111111111111111111111")
                            metas_init = [
                                AccountMeta(derived, False, True),
                                AccountMeta(wsol_mint, False, False),
                                AccountMeta(payer_pk, False, False),
                                AccountMeta(rent_pk, False, False),
                            ]
                            init_ix = SInstruction(token_program, bytes([1]), tuple(metas_init))
                            wrap_ixs.append(init_ix)
                            if not postunwrap:
                                postunwrap.append({"kind": "unwrap", "ata": recv0_key})
                    except Exception:
                        pass
        except Exception:
            pass
        # 1) Wraps (transfer + syncNative). La creación de ATA ya se programa en create_atas.
        for w in prewrap:
            try:
                ata_pk = Pubkey.from_string(w.get("ata"))
                lamports = int(w.get("lamports", 0))
                # transfer lamports al ATA WSOL (SOL->ATA)
                from solders.system_program import transfer, TransferParams  # type: ignore
                ix_tr = transfer(TransferParams(from_pubkey=payer_pk, to_pubkey=ata_pk, lamports=lamports))
                wrap_ixs.append(ix_tr)
                if self.logger.isEnabledFor(logging.INFO):
                    try:
                        self.logger.info("assemble_v0: wrap transfer ix añadido (lamports=%d)", lamports)
                    except Exception:
                        pass
                # syncNative (manual): tag 17, cuentas: [account]
                ix_sn = SInstruction(token_program, bytes([17]), tuple([AccountMeta(ata_pk, False, True)]))
                wrap_ixs.append(ix_sn)
                if self.logger.isEnabledFor(logging.INFO):
                    try:
                        data = getattr(ix_sn, "data", None)
                        self.logger.info("assemble_v0: wrap sync_native ix añadido data_type=%s", (type(data).__name__ if data is not None else None))
                    except Exception:
                        pass
            except Exception as exc:
                if self.logger.isEnabledFor(logging.ERROR):
                    try:
                        self.logger.error("assemble_v0: error añadiendo wrap (transfer+sync): %s", exc)
                    except Exception:
                        pass
                continue
        # Fallback de seguridad: si hay prewrap pero no se añadió transfer/syncNative, forzarlos
        try:
            have_transfer = False
            have_sync = False
            for ix in wrap_ixs:
                try:
                    pid = getattr(ix, "program_id", None)
                    if pid is not None and str(pid) == str(sys_program):
                        have_transfer = True
                    if pid is not None and str(pid) == str(token_program):
                        # Puede ser syncNative o create ATA; distinguimos por data tag si posible
                        data = getattr(ix, "data", b"")
                        tag = None
                        try:
                            tag = int(data[0]) if isinstance(data, (bytes, bytearray)) and len(data) > 0 else None
                        except Exception:
                            tag = None
                        if tag == 17:
                            have_sync = True
                except Exception:
                    continue
            if prewrap and not (have_transfer and have_sync):
                # Tomar el primer prewrap y crear transfer+syncNative
                for w in prewrap:
                    try:
                        ata_pk = Pubkey.from_string(w.get("ata"))
                        lamports = int(w.get("lamports", 0))
                        if lamports <= 0:
                            continue
                        from solders.system_program import transfer, TransferParams  # type: ignore
                        ix_tr = transfer(TransferParams(from_pubkey=payer_pk, to_pubkey=ata_pk, lamports=lamports))
                        wrap_ixs.append(ix_tr)
                        ix_sn = SInstruction(token_program, bytes([17]), tuple([AccountMeta(ata_pk, False, True)]))
                        wrap_ixs.append(ix_sn)
                        if self.logger.isEnabledFor(logging.INFO):
                            try:
                                self.logger.info("assemble_v0: fallback wrap (transfer+syncNative) añadido (lamports=%d)", lamports)
                            except Exception:
                                pass
                        break
                    except Exception as exc:
                        if self.logger.isEnabledFor(logging.ERROR):
                            try:
                                self.logger.error("assemble_v0: fallback wrap error: %s", exc)
                            except Exception:
                                pass
                        continue
        except Exception:
            pass
        unwrap_ixs: List[Any] = []
        for u in postunwrap:
            try:
                ata_pk = Pubkey.from_string(u.get("ata"))
                # closeAccount(owner recibe lamports)
                # close_account (manual): tag 9, cuentas: [account(w), destination(w), owner(s)]
                metas = [
                    AccountMeta(ata_pk, False, True),
                    AccountMeta(payer_pk, False, True),
                    AccountMeta(payer_pk, True, False),
                ]
                ix_ca = SInstruction(token_program, bytes([9]), tuple(metas))
                unwrap_ixs.append(ix_ca)
                if self.logger.isEnabledFor(logging.INFO):
                    try:
                        data = getattr(ix_ca, "data", None)
                        self.logger.info("assemble_v0: unwrap close_account ix añadido data_type=%s", (type(data).__name__ if data is not None else None))
                    except Exception:
                        pass
            except Exception:
                continue
        def _ensure_solders_ix(ix: Any) -> SInstruction:
            # Si ya es solders Instruction, reempaquetar garantizando bytes en data
            if isinstance(ix, SInstruction):
                db = ix.data
                if isinstance(db, (bytes, bytearray)):
                    dbb = bytes(db)
                elif isinstance(db, list):
                    try:
                        dbb = bytes(bytearray(int(x) & 0xFF for x in db))
                    except Exception:
                        dbb = bytes(str(db), "utf-8")
                elif isinstance(db, memoryview):
                    dbb = bytes(db)
                else:
                    try:
                        dbb = bytes(db)
                    except Exception:
                        dbb = bytes(str(db), "utf-8")
                return SInstruction(ix.program_id, dbb, tuple(ix.accounts))
            # Intentar reconstruir desde objetos similares (solana-py)
            try:
                prog = getattr(ix, "program_id", None) or getattr(ix, "programId", None)
                keys = getattr(ix, "accounts", None) or getattr(ix, "keys", None)
                data = getattr(ix, "data", None)
                if prog is None or keys is None:
                    raise RuntimeError("ix incompatible: falta program_id o keys")
                # program id a Pubkey
                if isinstance(prog, str):
                    prog_pk = Pubkey.from_string(prog)
                else:
                    prog_pk = Pubkey.from_string(str(prog))
                # keys a AccountMeta
                metas: List[AccountMeta] = []
                for k in list(keys):
                    if isinstance(k, dict):
                        pk_str = str(k.get("pubkey")) if k.get("pubkey") is not None else None
                        is_signer = bool(k.get("is_signer") or k.get("isSigner") or False)
                        is_writable = bool(k.get("is_writable") or k.get("isWritable") or False)
                    else:
                        pk = getattr(k, "pubkey", None)
                        pk_str = str(pk) if pk is not None else None
                        is_signer = getattr(k, "is_signer", None)
                        if is_signer is None:
                            is_signer = getattr(k, "isSigner", False)
                        is_writable = getattr(k, "is_writable", None)
                        if is_writable is None:
                            is_writable = getattr(k, "isWritable", False)
                    if not pk_str:
                        raise RuntimeError("account meta inválido en ix externo")
                    metas.append(AccountMeta(Pubkey.from_string(pk_str), bool(is_signer), bool(is_writable)))
                # data a bytes
                db = b""
                if data is None:
                    db = b""
                elif isinstance(data, (bytes, bytearray)):
                    db = bytes(data)
                elif isinstance(data, list):
                    buf = bytearray()
                    for x in data:
                        if isinstance(x, int):
                            buf.append(x & 0xFF)
                        elif isinstance(x, (bytes, bytearray)):
                            buf.extend(x)
                        elif isinstance(x, str):
                            s = x.strip()
                            if s.startswith("0x"):
                                buf.extend(bytes.fromhex(s[2:]))
                            else:
                                buf.extend(s.encode("utf-8"))
                        else:
                            buf.extend(bytes(str(x), "utf-8"))
                    db = bytes(buf)
                elif isinstance(data, str):
                    s = data.strip()
                    if s.startswith("0x"):
                        try:
                            db = bytes.fromhex(s[2:])
                        except Exception:
                            db = s.encode("utf-8")
                    else:
                        db = s.encode("utf-8")
                else:
                    db = bytes(str(data), "utf-8")
                ins = SInstruction(prog_pk, db, tuple(metas))
                if self.logger.isEnabledFor(logging.INFO):
                    try:
                        self.logger.info("ensure_solders_ix: program=%s metas=%d data_len=%d", str(prog_pk), len(metas), len(db))
                    except Exception:
                        pass
                return ins
            except Exception as exc:
                raise RuntimeError(f"No se pudo convertir ix a solders: {exc}")

        # Convertir extra_anchor_ixs (si vienen como descriptores anchor {program_id, keys, data}) a SInstruction
        extra_solders: List[Any] = []
        for eix in (extra_anchor_ixs or []):
            try:
                if isinstance(eix, dict) and eix.get("program_id") and eix.get("keys") is not None:
                    prog_pk = Pubkey.from_string(str(eix.get("program_id")))
                    ekeys = []
                    for k in (eix.get("keys") or []):
                        if not isinstance(k, dict) or not k.get("pubkey"):
                            continue
                        ekeys.append(AccountMeta(Pubkey.from_string(str(k.get("pubkey"))), bool(k.get("is_signer")), bool(k.get("is_writable"))))
                    edata = eix.get("data")
                    if isinstance(edata, (bytes, bytearray)):
                        edb = bytes(edata)
                    elif isinstance(edata, list):
                        buf = bytearray()
                        for x in edata:
                            if isinstance(x, int):
                                buf.append(x & 0xFF)
                            elif isinstance(x, (bytes, bytearray)):
                                buf.extend(x)
                            elif isinstance(x, str):
                                s = x.strip()
                                if s.startswith("0x"):
                                    buf.extend(bytes.fromhex(s[2:]))
                                else:
                                    buf.extend(s.encode("utf-8"))
                            else:
                                buf.extend(bytes(str(x), "utf-8"))
                        edb = bytes(buf)
                    elif isinstance(edata, str):
                        s = edata.strip()
                        if s.startswith("0x"):
                            try:
                                edb = bytes.fromhex(s[2:])
                            except Exception:
                                edb = s.encode("utf-8")
                        else:
                            edb = s.encode("utf-8")
                    else:
                        edb = b""
                    extra_solders.append(SInstruction(prog_pk, edb, tuple(ekeys)))
            except Exception:
                continue
        all_ixs_raw = ([] if ix_cu_price is None else [ix_cu_price]) + ([] if ix_cu_limit is None else [ix_cu_limit]) + wrap_ixs + [anchor_ix] + unwrap_ixs + extra_solders
        # Detección temprana: identificar cualquier ix cuya data sea list
        try:
            for i, ix in enumerate(all_ixs_raw):
                prog = getattr(ix, "program_id", None) or getattr(ix, "programId", None)
                data = getattr(ix, "data", None)
                if isinstance(data, list):
                    head = None
                    try:
                        head = str(data[:12])
                    except Exception:
                        head = None
                    self.logger.error("assemble_v0 detect: list data at raw index %d program=%s head=%s", i, (str(prog) if prog is not None else type(ix).__name__), head)
        except Exception:
            pass
        if self.logger.isEnabledFor(logging.INFO):
            try:
                dump_raw = []
                for i, ix in enumerate(all_ixs_raw):
                    prog = getattr(ix, "program_id", None) or getattr(ix, "programId", None)
                    data = getattr(ix, "data", None)
                    dump_raw.append({
                        "i": i,
                        "program": (str(prog) if prog is not None else type(ix).__name__),
                        "data_type": (type(data).__name__ if data is not None else None),
                    })
                self.logger.info("assemble_v0 raw ixs: %s", dump_raw)
            except Exception:
                pass
        # Convertir ixs una a una para identificar exactamente cuál falla y por qué
        all_ixs = []
        for i, ix in enumerate(all_ixs_raw):
            # Si ya es solders.Instruction, NO lo reconstruyas; úsalo tal cual
            try:
                from solders.instruction import Instruction as SoldersInstruction  # type: ignore
            except Exception:
                SoldersInstruction = None  # type: ignore
            is_solders = (SoldersInstruction is not None and isinstance(ix, SoldersInstruction))
            if is_solders:
                if self.logger.isEnabledFor(logging.INFO):
                    try:
                        raw_prog = getattr(ix, "program_id", None)
                        raw_data = getattr(ix, "data", None)
                        self.logger.info("assemble_v0 keep ix[%d]: program=%s data_type=%s", i, (str(raw_prog) if raw_prog is not None else type(ix).__name__), (type(raw_data).__name__ if raw_data is not None else None))
                    except Exception:
                        pass
                all_ixs.append(ix)
                continue
            # Caso contrario, convertimos
            try:
                raw_prog = getattr(ix, "program_id", None) or getattr(ix, "programId", None)
                raw_data = getattr(ix, "data", None)
                if self.logger.isEnabledFor(logging.INFO):
                    try:
                        dt = type(raw_data).__name__ if raw_data is not None else None
                        dl = (len(raw_data) if hasattr(raw_data, "__len__") else None)
                        self.logger.info("assemble_v0 pre-convert ix[%d]: program=%s data_type=%s data_len=%s", i, (str(raw_prog) if raw_prog is not None else type(ix).__name__), dt, dl)
                    except Exception:
                        pass
                all_ixs.append(_ensure_solders_ix(ix))
            except Exception as exc:
                try:
                    keys = getattr(ix, "accounts", None) or getattr(ix, "keys", None)
                    klen = len(keys) if keys is not None and hasattr(keys, "__len__") else None
                    self.logger.error("ensure_solders_ix failed at index %d: %s | program=%s keys=%s data_type=%s data_repr_head=%s",
                                      i,
                                      exc,
                                      (str(raw_prog) if raw_prog is not None else type(ix).__name__),
                                      klen,
                                      (type(raw_data).__name__ if raw_data is not None else None),
                                      (str(raw_data)[:120] if raw_data is not None else None))
                except Exception:
                    pass
                raise
        try:
            # Uso posicional: (payer, instructions, address_lookup_table_accounts, recent_blockhash)
            rb = SolHash.from_string(recent_blockhash) if isinstance(recent_blockhash, str) else recent_blockhash
            msg = MessageV0.try_compile(payer_pk, all_ixs, [], rb)
        except Exception as exc:
            # Construir blob de depuración con ixs crudas y convertidas
            debug_blob: Dict[str, Any] = {"raw": [], "converted": []}
            try:
                for i, ix in enumerate(all_ixs_raw):
                    prog = getattr(ix, "program_id", None) or getattr(ix, "programId", None)
                    data = getattr(ix, "data", None)
                    debug_blob["raw"].append({
                        "i": i,
                        "cls": type(ix).__name__,
                        "program": (str(prog) if prog is not None else None),
                        "data_type": (type(data).__name__ if data is not None else None),
                        "data_len": (len(data) if hasattr(data, "__len__") else None),
                    })
            except Exception:
                pass
            try:
                for i, ix in enumerate(all_ixs):
                    dt = type(getattr(ix, "data", None)).__name__
                    dl = len(getattr(ix, "data", b"")) if hasattr(getattr(ix, "data", b""), "__len__") else None
                    debug_blob["converted"].append({
                        "i": i,
                        "program": str(getattr(ix, "program_id", None)),
                        "data_type": dt,
                        "data_len": dl,
                    })
            except Exception:
                pass
            if self.logger.isEnabledFor(logging.ERROR):
                try:
                    self.logger.error("assemble_v0 compile failed: %s debug=%s", exc, json.dumps(debug_blob, ensure_ascii=False))
                except Exception:
                    pass
            raise RuntimeError(f"assemble_v0 compile failed: {exc}")
        # En esta fase devolvemos el MessageV0 serializado (no firmado).
        # El firmado se realiza en swap_send reconstruyendo VersionedTransaction(msg, keypairs).
        # Extra signers (mint del NFT) provienen de anchor.ix.signers
        extras: List[str] = []
        try:
            ix_signers_map = ((anc.get("anchor") or {}).get("ix") or {}).get("signers") or {}
            if isinstance(ix_signers_map, dict):
                for _, s_b64 in ix_signers_map.items():
                    if isinstance(s_b64, str):
                        extras.append(s_b64)
        except Exception:
            pass
        # Devuelve tx sin firmar en base64 (la firma se hace en swap_send)
        if self.logger.isEnabledFor(logging.INFO):
            try:
                self.logger.info(
                    "assemble_v0: ixs(cu+wrap+anchor+unwrap)=%d, prewrap=%d, postunwrap=%d, createATAs=%d",
                    2 + len(wrap_ixs) + 1 + len(unwrap_ixs), len(prewrap), len(postunwrap), len(create_atas),
                )
            except Exception:
                pass
        tx_b64 = __import__("base64").b64encode(bytes(msg)).decode("utf-8")
        return tx_b64, extras

    def swap_send(self, prep: Dict[str, Any], wait: bool = True) -> Dict[str, Any]:
        try:
            from solana.rpc.api import Client  # type: ignore
            from solana.rpc.types import TxOpts  # type: ignore
            from solders.transaction import VersionedTransaction  # type: ignore
            from solders.signature import Signature as SolSig  # type: ignore
            from solders.keypair import Keypair  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"Faltan dependencias para V0: {exc}")

        kp = self._load_solana_keypair()
        client = self._rpc_client()
        signatures: List[str] = []
        receipts: List[Dict[str, Any]] = []

        def _extract_sig(resp_obj: Any) -> Optional[str]:
            if isinstance(resp_obj, dict):
                return resp_obj.get("result") or resp_obj.get("value") or resp_obj.get("signature")
            val = getattr(resp_obj, "value", None)
            if isinstance(val, str):
                return val
            try:
                s = str(resp_obj)
                if not s:
                    return None
                import re
                m = re.search(r"Signature\(([1-9A-HJ-NP-Za-km-z]{32,})\)", s)
                if m:
                    return m.group(1)
                return s
            except Exception:
                return None

        def _to_jsonable(obj: Any) -> Any:
            if isinstance(obj, (str, int, float, bool)) or obj is None:
                return obj
            if isinstance(obj, dict):
                return {k: _to_jsonable(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_to_jsonable(x) for x in obj]
            val = getattr(obj, "value", None)
            if val is not None:
                return {"value": _to_jsonable(val)}
            to_dict = getattr(obj, "to_dict", None)
            if callable(to_dict):
                try:
                    return to_dict()
                except Exception:
                    pass
            try:
                return str(obj)
            except Exception:
                return None

        def _is_valid_sig(sig: Optional[str]) -> bool:
            if not isinstance(sig, str) or not sig:
                return False
            # placeholder común cuando el RPC está rate limited
            if sig == "1111111111111111111111111111111111111111111111111111111111111111":
                return False
            try:
                import re
                # Base58 chars y longitud típica (>=43)
                return re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{43,88}", sig) is not None
            except Exception:
                return True

        extra_signers: List[Any] = []
        try:
            flat_extras = prep.get("extraSigners") or []
            if not flat_extras:
                anchor_sign_map = ((prep.get("anchor") or {}).get("signers") or {})
                if isinstance(anchor_sign_map, dict):
                    flat_extras = list(anchor_sign_map.values())
            for s in flat_extras:
                try:
                    raw = __import__("base64").b64decode(str(s))
                    extra_signers.append(Keypair.from_bytes(raw))
                except Exception:
                    continue
        except Exception:
            pass

        for tx_b64 in prep.get("transactions", []):
            raw = __import__("base64").b64decode(tx_b64)
            sig: Optional[str] = None
            # 1) Intentar decodificar como MessageV0 y firmar localmente
            try:
                from solders.message import MessageV0  # type: ignore
                msg = MessageV0.from_bytes(raw)
                # Construir lista de firmantes requerida en orden
                ordered_signers: List[Any] = []
                try:
                    hdr = getattr(msg, "header", None)
                    num_req = int(getattr(hdr, "num_required_signatures", 0)) if hdr is not None else 0
                    signer_map = {str(kp.pubkey()): kp}
                    for ex in (extra_signers or []):
                        try:
                            signer_map[str(ex.pubkey())] = ex
                        except Exception:
                            continue
                    try:
                        static_keys = [str(pk) for pk in list(getattr(msg, "static_account_keys", []) or [])]
                    except Exception:
                        static_keys = []
                    if not static_keys:
                        ordered_signers = [kp] + list((extra_signers or []))
                        if num_req > 0:
                            ordered_signers = ordered_signers[:num_req]
                    else:
                        required_keys = static_keys[:num_req] if num_req > 0 else []
                        for sk in required_keys:
                            s_obj = signer_map.get(sk)
                            if s_obj is None and sk == str(kp.pubkey()):
                                s_obj = kp
                            if s_obj is not None:
                                ordered_signers.append(s_obj)
                        if num_req > 0 and len(ordered_signers) > num_req:
                            ordered_signers = ordered_signers[:num_req]
                        if num_req > 0 and len(ordered_signers) < num_req and self.logger.isEnabledFor(logging.ERROR):
                            self.logger.error("firmado insuficiente tras ordenar: required=%d provided=%d", num_req, len(ordered_signers))
                except Exception:
                    ordered_signers = [kp] + list((extra_signers or []))
                vtx = VersionedTransaction(msg, ordered_signers)
            except Exception:
                # 2) Si no es un mensaje, intentar decodificar como tx completa y re-firmarla con nuestro keypair
                try:
                    tmp_vtx = VersionedTransaction.from_bytes(raw)
                    # reconstruir orden de firmantes y firmar sobre el message de la tx
                    msg = getattr(tmp_vtx, "message", None)
                    if msg is None:
                        raise ValueError("transaction sin message")
                    ordered_signers: List[Any] = []
                    try:
                        hdr = getattr(msg, "header", None)
                        num_req = int(getattr(hdr, "num_required_signatures", 0)) if hdr is not None else 0
                        signer_map = {str(kp.pubkey()): kp}
                        for ex in (extra_signers or []):
                            try:
                                signer_map[str(ex.pubkey())] = ex
                            except Exception:
                                continue
                        try:
                            static_keys = [str(pk) for pk in list(getattr(msg, "static_account_keys", []) or [])]
                        except Exception:
                            static_keys = []
                        if not static_keys:
                            ordered_signers = [kp] + list((extra_signers or []))
                            if num_req > 0:
                                ordered_signers = ordered_signers[:num_req]
                        else:
                            required_keys = static_keys[:num_req] if num_req > 0 else []
                            for sk in required_keys:
                                s_obj = signer_map.get(sk)
                                if s_obj is None and sk == str(kp.pubkey()):
                                    s_obj = kp
                                if s_obj is not None:
                                    ordered_signers.append(s_obj)
                            if num_req > 0 and len(ordered_signers) > num_req:
                                ordered_signers = ordered_signers[:num_req]
                            if num_req > 0 and len(ordered_signers) < num_req and self.logger.isEnabledFor(logging.ERROR):
                                self.logger.error("firmado insuficiente tras ordenar: required=%d provided=%d", num_req, len(ordered_signers))
                    except Exception:
                        ordered_signers = [kp] + list((extra_signers or []))
                    vtx = VersionedTransaction(msg, ordered_signers)
                except Exception as exc_build:
                    self.logger.error("Error construyendo VersionedTransaction: %s", exc_build)
                    receipts.append({"error": str(exc_build)})
                    continue
            # 3) Enviar una sola vez; si la firma es inválida, reportar error sin reintentos
            try:
                opts = TxOpts(skip_preflight=False, preflight_commitment="confirmed", max_retries=0)
                resp = client.send_raw_transaction(bytes(vtx), opts=opts)
                sig = _extract_sig(resp)
            except Exception as exc:
                self.logger.error("Error enviando transacción v0: %s", exc)
                receipts.append({"error": str(exc)})
                continue
            if not _is_valid_sig(sig):
                self.logger.error("Firma no válida o placeholder devuelta por el RPC")
                receipts.append({"error": "firma inválida del RPC"})
                continue

            signatures.append(sig)
            if wait and sig:
                try:
                    sig_obj = SolSig.from_string(sig) if isinstance(sig, str) else sig
                    conf = client.confirm_transaction(sig_obj, commitment="confirmed")
                    receipts.append(_to_jsonable(conf))
                except Exception as exc:
                    receipts.append({"warn": f"confirm failed: {exc}"})

        return {"signatures": signatures, "receipts": receipts}

    def swap(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience: prepara y envía un swap en un único método."""
        # Si no es un swap_quote (falta swapResponse), autogenerarlo con get_quote
        swap_input = params or {}
        if not isinstance(swap_input, dict):
            raise ValueError("params inválido para swap")
        if "swapResponse" not in swap_input:
            kind = swap_input.get("kind") or swap_input.get("type") or "exact_in"
            input_mint = swap_input.get("inputMint") or swap_input.get("input_mint")
            output_mint = swap_input.get("outputMint") or swap_input.get("output_mint")
            amount = (
                swap_input.get("amount")
                or swap_input.get("amount_in")
                or swap_input.get("amountIn")
            )
            slippage_bps = (
                swap_input.get("slippage_bps")
                or swap_input.get("slippageBps")
                or 50
            )
            if not input_mint or not output_mint or amount is None:
                raise ValueError("Faltan campos para construir quote: inputMint, outputMint, amount")
            quote = self.get_quote(
                str(input_mint), str(output_mint), int(amount), str(kind), int(slippage_bps)
            )
            swap_input = quote
        prep = self.swap_prepare(swap_input)
        return self.swap_send(prep)

    def send_versioned_tx_base64(self, tx_b64: str, wait: bool = True) -> Dict[str, Any]:
        """Envía una transacción V0 en base64 directamente (firma con la keypair configurada).
        Devuelve {signature, confirmation?}.
        """
        try:
            from solana.rpc.api import Client  # type: ignore
            from solana.rpc.types import TxOpts  # type: ignore
            from solders.transaction import VersionedTransaction  # type: ignore
            from solders.signature import Signature as SolSig  # type: ignore
            from solders.keypair import Keypair  # type: ignore
            from solders.message import MessageV0  # type: ignore
        except Exception as exc:  # pragma: no cover
            return {"ok": False, "error": f"Faltan dependencias para V0: {exc}"}

        kp = self._load_solana_keypair()
        client = self._rpc_client()
        try:
            raw = __import__("base64").b64decode(tx_b64)
        except Exception as exc:
            return {"ok": False, "error": f"tx_b64 inválida: {exc}"}

        # Intentar decodificar como tx completa; si es message, firmar con kp
        vtx = None
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception:
            vtx = None
        if vtx is None:
            try:
                msg = MessageV0.from_bytes(raw)
                vtx = VersionedTransaction(msg, [kp])
            except Exception as exc:
                return {"ok": False, "error": f"No se pudo reconstruir VersionedTransaction: {exc}"}

        try:
            opts = TxOpts(skip_preflight=True, preflight_commitment="confirmed")
            resp = client.send_raw_transaction(bytes(vtx), opts=opts)
            # Extraer firma de forma robusta (dict | objeto | string)
            sig: Optional[str] = None
            if isinstance(resp, dict):
                sig = resp.get("result") or resp.get("value") or resp.get("signature")
            if not sig:
                val = getattr(resp, "value", None)
                if isinstance(val, str):
                    sig = val
            if not sig:
                try:
                    s = str(resp)
                    # Buscar patrón Signature(<base58>)
                    import re as _re
                    m = _re.search(r"Signature\(([1-9A-HJ-NP-Za-km-z]{32,})\)", s)
                    if m:
                        sig = m.group(1)
                    else:
                        sig = s
                except Exception:
                    sig = None
            out: Dict[str, Any] = {"ok": True, "signature": sig}
            if wait and isinstance(sig, str):
                try:
                    sig_obj = SolSig.from_string(sig)
                    conf = client.confirm_transaction(sig_obj, commitment="confirmed")
                    out["confirmation"] = conf
                except Exception as cexc:
                    out["warn"] = f"confirm failed: {cexc}"
            return out
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---------------- HTTP helpers (Raydium Trade API) ----------------
    def _api_get(self, path: str, params: Optional[Dict[str, Any]] = None, timeout: int = 20) -> Dict[str, Any]:
        import requests
        url = self.config.api_base.rstrip("/") + "/" + path.lstrip("/")
        r = requests.get(url, params=params or {}, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"data": data}
        return data

    def _api_post(self, path: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        import requests
        url = self.config.api_base.rstrip("/") + "/" + path.lstrip("/")
        r = requests.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"data": data}
        return data

    # ---------------- Raydium Info API (api-v3) ----------------
    def _info_api_get(self, path: str, params: Optional[Dict[str, Any]] = None, timeout: int = 20) -> Dict[str, Any]:
        import requests
        base = "https://api-v3.raydium.io"
        url = base.rstrip("/") + "/" + path.lstrip("/")
        r = requests.get(url, params=params or {}, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"data": data}
        return data

    def get_pool_info(self, pool_id: str) -> Dict[str, Any]:
        """Obtiene la información pública de una pool desde Raydium Info API.
        Retorna el objeto de la pool (dict) o {} si no se encuentra.
        """
        if not pool_id:
            raise ValueError("pool_id es obligatorio")
        data = self._info_api_get("pools/info/ids", params={"ids": pool_id})
        if isinstance(data, dict) and data.get("success") is False and data.get("message"):
            raise RuntimeError(f"Raydium info error: {data.get('message')}")
        payload = data.get("data") if isinstance(data, dict) else None
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and item.get("id") == pool_id:
                    return item
            return payload[0] if payload else {}
        return payload or {}

    # ---------------- Priority fee helper ----------------
    def _get_priority_fee_micro_lamports(self) -> Optional[int]:
        """Obtiene computeUnitPriceMicroLamports según tier (vh/h/m) usando la API si es posible.
        Si falla, devuelve None y el llamante puede omitir el campo.
        """
        try:
            # Endpoint esperado: /priority-fee
            data = self._api_get("priority-fee")
            tiers = (((data or {}).get("data") or {}).get("default") or {})
            val = tiers.get(self.config.priority_fee_tier)
            return int(val) if val is not None else None
        except Exception:
            return None

    def _derive_owner_from_keypair(self, keypair_path: str) -> str:
        import base58  # type: ignore
        from nacl.signing import SigningKey  # type: ignore

        expanded_path = os.path.expanduser(keypair_path)
        with open(expanded_path, "r", encoding="utf-8") as f:
            key_data = json.load(f)
        key_bytes = bytes(key_data)
        seed = key_bytes[:32] if len(key_bytes) == 64 else key_bytes
        sk = SigningKey(seed)
        vk = sk.verify_key
        return base58.b58encode(vk.encode()).decode("utf-8")

    def _rpc_call_with_failover(self, method: str, params: List[Any]) -> Dict[str, Any]:
        import requests

        last_error: Optional[Exception] = None
        for _ in range(len(self.config.rpc_endpoints)):
            url = self.rpc.current
            try:
                resp = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                if "error" in data:
                    raise RuntimeError(f"RPC error from {url}: {data['error']}")
                return data
            except Exception as exc:
                self.logger.warning("RPC endpoint failed (%s): %s", url, exc)
                last_error = exc
                self.rpc.rotate()
        self.logger.error("Todos los endpoints RPC fallaron")
        raise RuntimeError("All RPC endpoints failed") from last_error

    def _derive_personal_position_pda(self, nft_mint_b58: str) -> Tuple[str, int]:
        try:
            from solders.pubkey import Pubkey  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Falta dependencia 'solders'. Instala con: pip install solders") from exc
        program = Pubkey.from_string(self.config.program_id_clmm)
        mint_pk = Pubkey.from_string(nft_mint_b58)
        pda, bump = Pubkey.find_program_address([b"position", bytes(mint_pk)], program)
        return str(pda), bump

    # ---------------- CLMM PDA helpers ----------------
    def _tick_array_span(self) -> int:
        """Número de ticks por TickArray (Raydium CLMM usa 60 en mainnet WSOL/USDC)."""
        return 60

    def compute_tick_array_start_index(self, tick_index: int, tick_spacing: int) -> int:
        """Calcula el start_index del TickArray que contiene tick_index.
        start = floor(tick_index / (tick_spacing * span)) * (tick_spacing * span)
        """
        span = self._tick_array_span()
        unit = int(tick_spacing) * int(span)
        if unit <= 0:
            raise ValueError("tick_spacing inválido para tick array")
        # División entera hacia menos infinito para tick negativos
        if tick_index >= 0:
            q = tick_index // unit
        else:
            # Asegura que -1 -> -1, -unit-1 -> -2, etc.
            q = -((-tick_index + unit - 1) // unit)
        return q * unit

    def _compute_tick_array_start_index_span(self, tick_index: int, tick_spacing: int, span: int) -> int:
        unit = int(tick_spacing) * int(span)
        if unit <= 0:
            raise ValueError("tick_spacing inválido para tick array")
        if tick_index >= 0:
            q = tick_index // unit
        else:
            q = -((-tick_index + unit - 1) // unit)
        return q * unit

    def _find_existing_tick_array_pda(self, pool_id: str, tick_index: int, tick_spacing: int) -> str:
        # Mantener consistencia: usar el span oficial (88)
        sp = self._tick_array_span()
        try:
            start_idx = self._compute_tick_array_start_index_span(tick_index, tick_spacing, sp)
            addr, _ = self.derive_tick_array_pda(pool_id, start_idx)
            # Preferimos coincidir seeds aunque no exista aún on-chain
            return addr
        except Exception:
            # Fallback mínimo y consistente
            return self.derive_tick_array_pda(pool_id, 0)[0]

    def derive_tick_array_pda(self, pool_id: str, start_index: int) -> Tuple[str, int]:
        """PDA de tick array.
        Prueba prefijos ("tick_array" | "tickarray"), órdenes ([prefix, pool, i32] | [prefix, i32, pool])
        y endianness (LE | BE). Devuelve la primera que exista on-chain, con fallback estable.
        """
        try:
            from solders.pubkey import Pubkey  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Falta dependencia 'solders'. Instala con: pip install solders") from exc
        program = Pubkey.from_string(self.config.program_id_clmm)
        pool_pk = Pubkey.from_string(pool_id)
        si = int(start_index)
        si_le = si.to_bytes(4, byteorder="little", signed=True)
        si_be = si.to_bytes(4, byteorder="big", signed=True)
        prefixes = [b"tick_array", b"tickarray"]
        orders = [
            lambda pref, pk, idx: [pref, bytes(pk), idx],
            lambda pref, pk, idx: [pref, idx, bytes(pk)],
        ]
        idx_bytes = [(si_le, "le"), (si_be, "be")]
        candidates: List[Tuple[str, int, bytes, str, str]] = []
        # Construir todas las variantes
        for pref in prefixes:
            for order in orders:
                for bts, endian in idx_bytes:
                    seeds = order(pref, pool_pk, bts)
                    pda, bump = Pubkey.find_program_address(seeds, program)
                    candidates.append((str(pda), bump, pref, "pool_idx" if order is orders[0] else "idx_pool", endian))
        # Seleccionar la primera que exista on-chain
        for addr, bump, pref, order_tag, endian in candidates:
            try:
                if self._get_account_info_base64(addr):
                    try:
                        self.logger.debug("tick_array PDA match on-chain addr=%s pref=%s order=%s endian=%s start=%s", addr, pref.decode(), order_tag, endian, si)
                    except Exception:
                        pass
                    return addr, bump
            except Exception:
                continue
        # Fallback preferente: prefijo sin guion bajo, orden [pref, pool, i32_le]
        seeds_fallback = [b"tickarray", bytes(pool_pk), si_le]
        pda_fb, bump_fb = Pubkey.find_program_address(seeds_fallback, program)
        try:
            self.logger.debug("tick_array PDA fallback addr=%s start=%s", str(pda_fb), si)
        except Exception:
            pass
        return str(pda_fb), bump_fb

    def derive_protocol_position_pda(self, pool_id: str, tick_lower: int, tick_upper: int) -> Tuple[str, int]:
        """PDA de protocol position.
        Prueba prefijos ("protocol_position" | "protocolposition") y endianness (LE | BE)
        para los índices lower/upper. Devuelve la primera que exista on-chain.
        """
        try:
            from solders.pubkey import Pubkey  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Falta dependencia 'solders'. Instala con: pip install solders") from exc
        program = Pubkey.from_string(self.config.program_id_clmm)
        pool_pk = Pubkey.from_string(pool_id)
        lo = int(tick_lower)
        hi = int(tick_upper)
        lo_le = lo.to_bytes(4, byteorder="little", signed=True)
        hi_le = hi.to_bytes(4, byteorder="little", signed=True)
        lo_be = lo.to_bytes(4, byteorder="big", signed=True)
        hi_be = hi.to_bytes(4, byteorder="big", signed=True)
        prefixes = [b"protocol_position", b"protocolposition"]
        idx_pairs = [(lo_le, hi_le, "le"), (lo_be, hi_be, "be")]
        candidates: List[Tuple[str, int, bytes, str]] = []
        for pref in prefixes:
            for lo_b, hi_b, endian in idx_pairs:
                seeds = [pref, bytes(pool_pk), lo_b, hi_b]
                pda, bump = Pubkey.find_program_address(seeds, program)
                candidates.append((str(pda), bump, pref, endian))
        for addr, bump, pref, endian in candidates:
            try:
                if self._get_account_info_base64(addr):
                    try:
                        self.logger.debug("protocol_position PDA match on-chain addr=%s pref=%s endian=%s lo=%s hi=%s", addr, pref.decode(), endian, lo, hi)
                    except Exception:
                        pass
                    return addr, bump
            except Exception:
                continue
        # Fallback: prefijo estándar y LE
        seeds_fb = [b"protocol_position", bytes(pool_pk), lo_le, hi_le]
        pda_fb, bump_fb = Pubkey.find_program_address(seeds_fb, program)
        try:
            self.logger.debug("protocol_position PDA fallback addr=%s lo=%s hi=%s", str(pda_fb), lo, hi)
        except Exception:
            pass
        return str(pda_fb), bump_fb

    def get_pool_state_decoded(self, pool_id: str) -> Dict[str, Any]:
        """Lee y decodifica la cuenta PoolState on-chain."""
        b64 = self._get_account_info_base64(pool_id)
        if not b64:
            raise RuntimeError(f"Cuenta de pool no encontrada: {pool_id}")
        return self._decode_account("PoolState", pool_id, b64) or {}

    def resolve_pool_id(self, token_a: str, token_b: str, fee_bps: int) -> Dict[str, Any]:
        """Resuelve pool CLMM por mints y fee (bps)."""
        pool = self._clmm_resolve_pool(token_a, token_b, int(fee_bps))
        if not pool:
            return {"ok": False, "error": "pool no encontrada", "args": {"token_a": token_a, "token_b": token_b, "fee_bps": int(fee_bps)}}
        pid = pool.get("id") or pool.get("poolId") or pool.get("address")
        return {"ok": True, "pool_id": pid, "pool": pool}

    def get_pool_state(self, pool_id: str) -> Dict[str, Any]:
        """Devuelve estado normalizado de la pool: tick_current, tick_spacing, liquidity_global, tokens."""
        if not pool_id:
            return {"ok": False, "error": "pool_id requerido"}
        st = self.get_pool_state_decoded(pool_id)
        # tick_current
        tick_current = self.get_pool_tick_current(pool_id)
        # tick_spacing
        tick_spacing = None
        for k in ("tick_spacing", "tickSpacing", "tick_spacing_index"):
            if isinstance(st, dict) and st.get(k) is not None:
                try:
                    tick_spacing = int(st.get(k))
                    break
                except Exception:
                    continue
        # liquidity_global
        liquidity = None
        for k in ("liquidity", "liquidity_global", "global_liquidity"):
            if isinstance(st, dict) and st.get(k) is not None:
                try:
                    liquidity = int(st.get(k))
                    break
                except Exception:
                    continue
        # tokens mints
        m0, m1 = self.get_pool_mints(st)
        return {
            "ok": True,
            "pool_id": pool_id,
            "tick_current": tick_current,
            "tick_spacing": tick_spacing,
            "liquidity_global": liquidity,
            "tokens": {"A": {"mint": m0}, "B": {"mint": m1}},
        }

    def get_pool_vaults(self, pool_state: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extrae direcciones de vaults A/B desde el estado de la pool, tolerando nombres alternativos."""
        if not isinstance(pool_state, dict):
            return None, None
        for k0, k1 in (
            ("token_vault_0", "token_vault_1"),
            ("tokenVault0", "tokenVault1"),
            ("vault_0", "vault_1"),
            ("vaultA", "vaultB"),
        ):
            v0 = pool_state.get(k0)
            v1 = pool_state.get(k1)
            if isinstance(v0, str) and isinstance(v1, str):
                return v0, v1
        return None, None

    def get_pool_mints(self, pool_state: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extrae mints 0/1 desde el estado de la pool, tolerando nombres alternativos."""
        if not isinstance(pool_state, dict):
            return None, None
        # Chequear claves comunes
        candidates = [
            ("token_mint_0", "token_mint_1"),
            ("tokenMint0", "tokenMint1"),
            ("mint0", "mint1"),
            ("mintA", "mintB"),
        ]
        for k0, k1 in candidates:
            m0 = pool_state.get(k0)
            m1 = pool_state.get(k1)
            if isinstance(m0, str) and isinstance(m1, str):
                return m0, m1
        return None, None

    # ---------------- Anchor/Borsh encoders ----------------
    def _anchor_discriminator(self, ix_name: str) -> bytes:
        import hashlib
        h = hashlib.sha256(f"global:{ix_name}".encode("utf-8")).digest()
        return h[:8]

    def _encode_i32_le(self, val: int) -> bytes:
        return int(val).to_bytes(4, byteorder="little", signed=True)

    def _encode_u64_le(self, val: int) -> bytes:
        return int(val).to_bytes(8, byteorder="little", signed=False)

    def _encode_u128_le(self, val: int) -> bytes:
        return int(val).to_bytes(16, byteorder="little", signed=False)

    def _encode_bool(self, val: bool) -> bytes:
        return b"\x01" if bool(val) else b"\x00"

    def _encode_option_bool(self, val: Optional[bool]) -> bytes:
        if val is None:
            return b"\x00"
        return b"\x01" + self._encode_bool(bool(val))

    # ---------------- Build CLMM instructions (Anchor) ----------------
    def build_open_position_with_token22_ix(
        self,
        pool_id: str,
        mintA: str,
        mintB: str,
        tick_lower: int,
        tick_upper: int,
        amount0_max: int,
        amount1_max: int,
        with_metadata: bool = True,
        base_flag: Optional[bool] = False,
        tick_spacing_hint: Optional[int] = None,
        token_account_a: Optional[str] = None,
        token_account_b: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Construye estructura de instrucción Anchor para open_position_with_token22_nft.
        NOTA: requiere firmar también con un keypair efímero para el mint del NFT de posición.
        Devuelve dict con: {program_id, keys:[{pubkey,is_signer,is_writable}], data(bytes), signers:{mint:priv_b64}, accounts:{...}}
        """
        # 1) Estado de pool, spacing y vaults
        pool_state = self.get_pool_state_decoded(pool_id)
        # Determinar tickSpacing
        spacing = None
        for k in ("tick_spacing", "tickSpacing", "tick_spacing_index"):
            if pool_state.get(k) is not None:
                try:
                    spacing = int(pool_state.get(k)); break
                except Exception:
                    pass
        if spacing is None and tick_spacing_hint is not None:
            spacing = int(tick_spacing_hint)
        if spacing is None:
            raise RuntimeError("No se pudo determinar tickSpacing de la pool")
        vault0, vault1 = self.get_pool_vaults(pool_state)
        if not vault0 or not vault1:
            raise RuntimeError("No se pudieron determinar los vaults de la pool")
        mint0, mint1 = self.get_pool_mints(pool_state)

        # 2) Tick arrays
        start_lo = self.compute_tick_array_start_index(tick_lower, spacing)
        start_hi = self.compute_tick_array_start_index(tick_upper, spacing)
        # Derivar PDAs exactamente a partir de los start_index usados en la instrucción
        ta_lo, _ = self.derive_tick_array_pda(pool_id, start_lo)
        ta_hi, _ = self.derive_tick_array_pda(pool_id, start_hi)

        # 3) Position NFT mint (efímero)
        try:
            from solders.keypair import Keypair  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Falta dependencia solders: {exc}")
        mint_kp = Keypair()
        mint_pub = str(mint_kp.pubkey())
        # Personal position PDA
        personal_pos, _b = self._derive_personal_position_pda(mint_pub)
        # Protocol position PDA
        proto_pos, _pb = self.derive_protocol_position_pda(pool_id, tick_lower, tick_upper)

        # 4) Cuentas de entrada del usuario (token accounts)
        # Requerimos ATAs existentes para ambos mints (sin auto-wrap aquí)
        ata_a = token_account_a or (self._derive_ata(self.owner_pubkey, mintA) if not self._is_sol_mint(mintA) else None)
        ata_b = token_account_b or (self._derive_ata(self.owner_pubkey, mintB) if not self._is_sol_mint(mintB) else None)
        # Si alguno es SOL nativo, pedimos pre-wrap en notas (no gestionamos temp WSOL en esta versión)
        notes: List[str] = []
        if self._is_sol_mint(mintA):
            notes.append("mintA es SOL: pre-wrap a WSOL ATA y pásalo como Token Account 0")
        if self._is_sol_mint(mintB):
            notes.append("mintB es SOL: pre-wrap a WSOL ATA y pásalo como Token Account 1")
        if not ata_a and not self._is_sol_mint(mintA):
            notes.append("ATA de token A ausente")
        if not ata_b and not self._is_sol_mint(mintB):
            notes.append("ATA de token B ausente")

        # 5) Datos Borsh (Anchor) para la instrucción
        ix_name = "open_position_with_token22_nft"
        data = b"".join([
            self._anchor_discriminator(ix_name),
            self._encode_i32_le(int(tick_lower)),
            self._encode_i32_le(int(tick_upper)),
            self._encode_i32_le(int(start_lo)),
            self._encode_i32_le(int(start_hi)),
            self._encode_u128_le(0),  # liquidity=0 (program calcula por amounts max)
            self._encode_u64_le(int(amount0_max)),
            self._encode_u64_le(int(amount1_max)),
            self._encode_bool(bool(with_metadata)),
            self._encode_option_bool(base_flag),
        ])

        # 6) Claves: construir en el orden exacto del IDL
        schema = self.decoder.get_instruction_schema("open_position_with_token22_nft")
        acc_list = (schema.get("accounts") or []) if isinstance(schema, dict) else []
        # Derivaciones auxiliares
        rent_sysvar = "SysvarRent111111111111111111111111111111111"
        sys_program = "11111111111111111111111111111111"
        token_program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        token2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        ata_program = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        pos_nft_ata = self._derive_ata(self.owner_pubkey, mint_pub, token_program_id=token2022_program)
        name_map: Dict[str, str] = {
            "payer": self.owner_pubkey,
            "position_nft_owner": self.owner_pubkey,
            "nft_owner": self.owner_pubkey,
            "position_nft_mint": mint_pub,
            "nft_mint": mint_pub,
            "position_nft_account": pos_nft_ata or "",
            "nft_account": pos_nft_ata or "",
            "pool": pool_id,
            "pool_state": pool_id,
            "protocol_position": proto_pos,
            "tick_array_lower": ta_lo,
            "tickarraylower": ta_lo,
            "tick_array_upper": ta_hi,
            "tickarrayupper": ta_hi,
            "personal_position": personal_pos,
            "token_account_0": ata_a or "",
            "token_account_a": ata_a or "",
            "token_account_1": ata_b or "",
            "token_account_b": ata_b or "",
            "token_vault_0": vault0,
            "token_vault_a": vault0,
            "token_vault_1": vault1,
            "token_vault_b": vault1,
            "token_mint_0": (mint0 or ""),
            "token_mint_a": (mint0 or ""),
            "vault_0_mint": (mint0 or ""),
            "token_mint_1": (mint1 or ""),
            "token_mint_b": (mint1 or ""),
            "vault_1_mint": (mint1 or ""),
            "rent": rent_sysvar,
            "system_program": sys_program,
            "token_program": token_program,
            "token_program_2022": token2022_program,
            "associated_token_program": ata_program,
        }
        def resolve_account_name(n: str) -> Optional[str]:
            k = (n or "").replace(" ", "").replace("-", "_").lower()
            return name_map.get(k)
        keys: List[Dict[str, Any]] = []
        for a in acc_list:
            try:
                nm = str(a.get("name"))
                pk = resolve_account_name(nm)
                if not pk:
                    # fallback por alias comunes
                    if "tick" in nm.lower() and "lower" in nm.lower():
                        pk = ta_lo
                    elif "tick" in nm.lower() and "upper" in nm.lower():
                        pk = ta_hi
                    elif "vault" in nm.lower() and ("0" in nm or "a" in nm.lower()):
                        pk = vault0
                    elif "vault" in nm.lower() and ("1" in nm or "b" in nm.lower()):
                        pk = vault1
                if not pk:
                    pk = sys_program
                # Determinar flags signer/writable con overrides según nombre
                is_signer_flag = bool(a.get("isSigner"))
                is_writable_flag = bool(a.get("isMut"))
                nml = (nm or "").lower()
                if ("mint" in nml and ("nft" in nml or "position" in nml)):
                    is_signer_flag = True
                    is_writable_flag = True
                # Cuentas que el programa modifica en CPI deben ser writable
                if (
                    "personal_position" in nml
                    or "personalposition" in nml
                    or "protocol_position" in nml
                    or "protocolposition" in nml
                    or nml in ("pool", "pool_state")
                    or nml.startswith("tick_array")
                    or nml.startswith("tickarray")
                    or nml.startswith("token_vault")
                    or nml.startswith("tokenaccount")
                    or nml.startswith("token_account")
                    or "position_nft_account" in nml
                    or "nft_account" in nml
                ):
                    is_writable_flag = True
                keys.append({
                    "pubkey": pk,
                    "is_signer": is_signer_flag,
                    "is_writable": is_writable_flag,
                })
            except Exception:
                continue

        return {
            "program_id": self.config.program_id_clmm,
            "keys": keys,
            "data": data,
            "accounts": {
                "pool": pool_id,
                "tickArrays": {"lower": ta_lo, "upper": ta_hi, "start": {"lower": start_lo, "upper": start_hi}},
                "personalPosition": personal_pos,
                "protocolPosition": proto_pos,
                "vaults": {"A": vault0, "B": vault1},
                "positionNft": {"mint": mint_pub, "owner": self.owner_pubkey, "ata": self._derive_ata(self.owner_pubkey, mint_pub)},
                "tokenAccounts": {"A": ata_a, "B": ata_b},
            },
            "signers": {
                "positionNftMint": __import__("base64").b64encode(bytes(mint_kp)).decode("utf-8"),
            },
            "notes": notes,
        }

    def liquidity_prepare_anchor_open(
        self,
        mintA: str,
        mintB: str,
        pool_id: str,
        tick_lower: int,
        tick_upper: int,
        amountA_desired: int,
        amountB_desired: int,
        slippage_bps: int = 50,
        compute_unit_price_micro: int = 25_000,
        compute_unit_limit: int = 600_000,
    ) -> Dict[str, Any]:
        """Prepara instrucción Anchor para abrir posición CLMM con Token-2022 NFT.
        Devuelve estructura con ix Anchor y parámetros de Compute Budget. No compila ni firma la tx.
        """
        # mínimos/máximos por slippage (cliente) + pequeño headroom de ejecución
        slip = max(0, int(slippage_bps))
        a_min = (int(amountA_desired) * (10000 - slip)) // 10000
        b_min = (int(amountB_desired) * (10000 - slip)) // 10000
        # Añadimos 100 bps de colchón adicional para cubrir redondeos/cambios intra-bloque
        exec_buf_bps = 100
        headroom_bps = min(20000, slip + exec_buf_bps)
        a_max = (int(amountA_desired) * (10000 + headroom_bps)) // 10000
        b_max = (int(amountB_desired) * (10000 + headroom_bps)) // 10000
        notes: List[str] = []
        try:
            # Si hay SOL, crear cuentas WSOL temporales (ATAs) como token accounts explícitos
            token_account_a = None
            token_account_b = None
            prewrap: List[Dict[str, Any]] = []
            postunwrap: List[Dict[str, Any]] = []
            createATAs: List[Dict[str, Any]] = []
            if self._is_sol_mint(mintA):
                token_account_a = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
                prewrap.append({"kind": "wrap", "mint": self.SOL_MINT, "ata": token_account_a, "lamports": int(a_max)})
                postunwrap.append({"kind": "unwrap", "ata": token_account_a})
                try:
                    exists_a = self._ata_exists(token_account_a)
                except Exception:
                    exists_a = None
                if exists_a is False:
                    createATAs.append({"owner": self.owner_pubkey, "mint": self.SOL_MINT})
            if self._is_sol_mint(mintB):
                token_account_b = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
                prewrap.append({"kind": "wrap", "mint": self.SOL_MINT, "ata": token_account_b, "lamports": int(b_max)})
                postunwrap.append({"kind": "unwrap", "ata": token_account_b})
                try:
                    exists_b = self._ata_exists(token_account_b)
                except Exception:
                    exists_b = None
                if exists_b is False:
                    createATAs.append({"owner": self.owner_pubkey, "mint": self.SOL_MINT})
            # Crear ATAs si faltan (tokens no SOL)
            if not self._is_sol_mint(mintA):
                try:
                    ata_a_check = self._derive_ata(self.owner_pubkey, mintA)
                    exists_a = self._ata_exists(ata_a_check)
                    if exists_a is False:
                        createATAs.append({"owner": self.owner_pubkey, "mint": mintA})
                except Exception:
                    pass
            if not self._is_sol_mint(mintB):
                try:
                    ata_b_check = self._derive_ata(self.owner_pubkey, mintB)
                    exists_b = self._ata_exists(ata_b_check)
                    if exists_b is False:
                        createATAs.append({"owner": self.owner_pubkey, "mint": mintB})
                except Exception:
                    pass
            # Aporte dual por defecto; mantenemos prewrap si hay SOL en A o B
            adj_amount0 = int(a_max)
            adj_amount1 = int(b_max)
            base_flag_val: Optional[bool] = False
            ix = self.build_open_position_with_token22_ix(
                pool_id=pool_id,
                mintA=mintA,
                mintB=mintB,
                tick_lower=int(tick_lower),
                tick_upper=int(tick_upper),
                amount0_max=adj_amount0,
                amount1_max=adj_amount1,
                with_metadata=True,
                base_flag=base_flag_val,
                token_account_a=token_account_a,
                token_account_b=token_account_b,
            )
        except Exception as exc:
            return {"canSend": False, "error": str(exc), "notes": [str(exc)]}
        cb = {"microLamports": int(compute_unit_price_micro), "units": int(compute_unit_limit)}
        # Advertencias si faltan ATAs o si hay SOL nativo
        accs = (ix or {}).get("accounts") or {}
        tacc = (accs.get("tokenAccounts") or {})
        if (tacc.get("A") is None) and (mintA != self.SOL_MINT):
            notes.append("Falta ATA de token A para el owner")
        if (tacc.get("B") is None) and (mintB != self.SOL_MINT):
            notes.append("Falta ATA de token B para el owner")
        if mintA == self.SOL_MINT or mintB == self.SOL_MINT:
            notes.append("Requiere WSOL pre-wrap en ATA del owner")
        meta = {
            "poolId": pool_id,
            "ticks": {"lower": int(tick_lower), "upper": int(tick_upper)},
            "amounts": {"A": int(amountA_desired), "B": int(amountB_desired), "minA": int(a_min), "minB": int(b_min)},
            "computeBudget": cb,
        }
        return {"anchor": {"ix": ix, "computeBudget": cb, "prewrap": prewrap, "postunwrap": postunwrap, "createATAs": createATAs}, "meta": meta, "canSend": False, "notes": notes}

    def build_increase_liquidity_ix(
        self,
        pool_id: str,
        position_nft_mint: str,
        mintA: str,
        mintB: str,
        tick_lower: int,
        tick_upper: int,
        amount0_max: int,
        amount1_max: int,
        tick_spacing_hint: Optional[int] = None,
        base_flag: Optional[bool] = True,
    ) -> Dict[str, Any]:
        """Construye instrucción Anchor para añadir liquidez a una posición existente.
        Requiere NFT mint de la posición para derivar el PDA personal.
        """
        pool_state = self.get_pool_state_decoded(pool_id)
        spacing = None
        for k in ("tick_spacing", "tickSpacing", "tick_spacing_index"):
            if pool_state.get(k) is not None:
                try:
                    spacing = int(pool_state.get(k)); break
                except Exception:
                    pass
        if spacing is None and tick_spacing_hint is not None:
            spacing = int(tick_spacing_hint)
        if spacing is None:
            raise RuntimeError("No se pudo determinar tickSpacing de la pool")
        vault0, vault1 = self.get_pool_vaults(pool_state)
        if not vault0 or not vault1:
            raise RuntimeError("No se pudieron determinar los vaults de la pool")

        start_lo = self.compute_tick_array_start_index(tick_lower, spacing)
        start_hi = self.compute_tick_array_start_index(tick_upper, spacing)
        ta_lo, _ = self.derive_tick_array_pda(pool_id, start_lo)
        ta_hi, _ = self.derive_tick_array_pda(pool_id, start_hi)
        personal_pos, _b = self._derive_personal_position_pda(position_nft_mint)
        proto_pos, _pb = self.derive_protocol_position_pda(pool_id, tick_lower, tick_upper)

        ata_a = self._derive_ata(self.owner_pubkey, mintA) if not self._is_sol_mint(mintA) else None
        ata_b = self._derive_ata(self.owner_pubkey, mintB) if not self._is_sol_mint(mintB) else None
        notes: List[str] = []
        if self._is_sol_mint(mintA):
            notes.append("mintA es SOL: pre-wrap WSOL en ATA")
        if self._is_sol_mint(mintB):
            notes.append("mintB es SOL: pre-wrap WSOL en ATA")

        ix_name = "increase_liquidity"
        data = b"".join([
            self._anchor_discriminator(ix_name),
            self._encode_i32_le(int(tick_lower)),
            self._encode_i32_le(int(tick_upper)),
            self._encode_i32_le(int(start_lo)),
            self._encode_i32_le(int(start_hi)),
            self._encode_u128_le(0),
            self._encode_u64_le(int(amount0_max)),
            self._encode_u64_le(int(amount1_max)),
            self._encode_option_bool(base_flag),
        ])

        keys: List[Dict[str, Any]] = [
            {"pubkey": self.owner_pubkey, "is_signer": True, "is_writable": True},
            {"pubkey": pool_id, "is_signer": False, "is_writable": True},
            {"pubkey": proto_pos, "is_signer": False, "is_writable": True},
            {"pubkey": ta_lo, "is_signer": False, "is_writable": True},
            {"pubkey": ta_hi, "is_signer": False, "is_writable": True},
            {"pubkey": personal_pos, "is_signer": False, "is_writable": True},
            {"pubkey": (ata_a or ""), "is_signer": False, "is_writable": True},
            {"pubkey": (ata_b or ""), "is_signer": False, "is_writable": True},
            {"pubkey": vault0, "is_signer": False, "is_writable": True},
            {"pubkey": vault1, "is_signer": False, "is_writable": True},
            {"pubkey": "11111111111111111111111111111111", "is_signer": False, "is_writable": False},
        ]
        for pid in (
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        ):
            keys.append({"pubkey": pid, "is_signer": False, "is_writable": False})

        return {
            "program_id": self.config.program_id_clmm,
            "keys": keys,
            "data": data,
            "accounts": {
                "pool": pool_id,
                "tickArrays": {"lower": ta_lo, "upper": ta_hi, "start": {"lower": start_lo, "upper": start_hi}},
                "personalPosition": personal_pos,
                "protocolPosition": proto_pos,
                "vaults": {"A": vault0, "B": vault1},
                "tokenAccounts": {"A": ata_a, "B": ata_b},
                "positionNftMint": position_nft_mint,
            },
            "notes": notes,
        }

    def liquidity_prepare_anchor_increase(
        self,
        pool_id: str,
        position_nft_mint: str,
        mintA: str,
        mintB: str,
        tick_lower: int,
        tick_upper: int,
        amountA_desired: int,
        amountB_desired: int,
        slippage_bps: int = 50,
        compute_unit_price_micro: int = 25_000,
        compute_unit_limit: int = 600_000,
    ) -> Dict[str, Any]:
        slip = max(0, int(slippage_bps))
        a_min = (int(amountA_desired) * (10000 - slip)) // 10000
        b_min = (int(amountB_desired) * (10000 - slip)) // 10000
        try:
            ix = self.build_increase_liquidity_ix(
                pool_id=pool_id,
                position_nft_mint=position_nft_mint,
                mintA=mintA,
                mintB=mintB,
                tick_lower=int(tick_lower),
                tick_upper=int(tick_upper),
                amount0_max=int(amountA_desired),
                amount1_max=int(amountB_desired),
            )
        except Exception as exc:
            return {"canSend": False, "error": str(exc), "notes": [str(exc)]}
        cb = {"microLamports": int(compute_unit_price_micro), "units": int(compute_unit_limit)}
        meta = {
            "poolId": pool_id,
            "position": position_nft_mint,
            "ticks": {"lower": int(tick_lower), "upper": int(tick_upper)},
            "amounts": {"A": int(amountA_desired), "B": int(amountB_desired), "minA": int(a_min), "minB": int(b_min)},
            "computeBudget": cb,
        }
        return {"anchor": {"ix": ix, "computeBudget": cb}, "meta": meta, "canSend": False, "notes": ix.get("notes") or []}

    def _get_account_info_base64(self, pubkey: str) -> Optional[str]:
        try:
            data = self._rpc_call_with_failover("getAccountInfo", [pubkey, {"encoding": "base64"}])
            result = data.get("result") or {}
            value = result.get("value") if isinstance(result, dict) else None
            if not value:
                self.logger.debug("Cuenta no encontrada: %s", pubkey)
                return None
            arr = value.get("data", [None, None]) if isinstance(value, dict) else [None, None]
            return arr[0]
        except Exception as exc:
            self.logger.error("Error obteniendo información de cuenta %s: %s", pubkey, exc)
            return None

    def _decode_account(self, account_type: str, pubkey: str, raw_b64: str) -> Dict[str, Any]:
        import base64  # type: ignore
        raw = base64.b64decode(raw_b64)
        return self.decoder.anchor_cli_decode(
            program_id=self.config.program_id_clmm,
            account_type=account_type,
            account_pubkey=pubkey,
            cluster=self.config.cluster,
            wallet_path=self.config.keypair_path,
        ) or {}

    def check_position_exists_tool(self, position_nft_mint: str) -> Dict[str, Any]:
        if not position_nft_mint:
            return {"exists": False, "details": {"reason": "missing position_nft_mint"}}
        try:
            # 1) Derivar PDA y leer posición
            acc_name, _, _ = self.decoder.infer_position_offsets()
            pda, _bump = self._derive_personal_position_pda(position_nft_mint)
            pos_b64 = self._get_account_info_base64(pda)
            if not pos_b64:
                return {"exists": False, "details": {}}
            pos_details = self._decode_account(acc_name, pda, pos_b64)
            if not isinstance(pos_details, dict):
                return {"exists": False, "details": {}}
            # 2) Leer pool y extraer tick actual (reutilizando helper)
            pool_id = pos_details.get("pool_id")
            current_tick: Optional[int] = None
            if isinstance(pool_id, str) and pool_id:
                current_tick = self.get_pool_tick_current(pool_id)
            else:
                self.logger.warning("pool_id inválido en posición: %s", pool_id)
            # 3) Unir y devolver
            merged = dict(pos_details)
            if current_tick is not None:
                merged["tick_current"] = current_tick
            return {"exists": True, "details": merged}
        except Exception as exc:
            self.logger.error("Error verificando posición %s: %s", position_nft_mint, exc)
            return {"exists": False, "details": {"error": f"position check failed: {exc}"}}

    def get_pool_tick_current(self, pool_id: str) -> Optional[int]:
        """Lee la cuenta on-chain de la pool CLMM y extrae el tick actual.
        Devuelve int o None si no se puede determinar.
        """
        if not pool_id:
            raise ValueError("pool_id es obligatorio")
        pool_b64 = self._get_account_info_base64(pool_id)
        if not pool_b64:
            self.logger.warning("Cuenta de pool no encontrada: %s", pool_id)
            return None
        details = self._decode_account("PoolState", pool_id, pool_b64)
        current_tick: Optional[int] = None
        for key in ("tick_current_index", "tickCurrentIndex", "tick_current", "current_tick_index"):
            if isinstance(details, dict) and key in details:
                try:
                    current_tick = int(details[key])
                    break
                except Exception:
                    continue
        if current_tick is None:
            self.logger.warning("tickCurrent no disponible en cuenta de pool %s", pool_id)
            
        return current_tick


    # ---------------- Liquidity REMOVE (decrease + close) ----------------
    def _read_position_core(self, position_nft_mint: str) -> Dict[str, Any]:
        details: Dict[str, Any] = {}
        try:
            acc_name, _, _ = self.decoder.infer_position_offsets()
        except Exception:
            acc_name = "PersonalPosition"
        pda, _bump = self._derive_personal_position_pda(position_nft_mint)
        pos_b64 = self._get_account_info_base64(pda)
        if not pos_b64:
            return {}
        details = self._decode_account(acc_name, pda, pos_b64)
        if not isinstance(details, dict):
            return {}
        details["pda"] = pda
        return details

    def position_belongs_to_pool(self, position: str, pool_id: Optional[str] = None) -> Dict[str, Any]:
        """Lee la posición por NFT y determina su estado; si no se pasa pool_id, lo resuelve desde la posición."""
        if not position:
            return {"ok": False, "error": "missing position"}
        pos = self._read_position_core(position)
        if not pos:
            return {"ok": False, "error": "position not found"}
        # Resolver pool_id desde la posición si no se proporcionó
        resolved_pool_id: Optional[str] = pool_id
        if not resolved_pool_id:
            for k in ("pool", "pool_id", "poolState", "pool_state", "poolId", "poolKey", "poolAddress"):
                if k in pos:
                    try:
                        v = pos[k]
                        if isinstance(v, str) and len(v) > 0:
                            resolved_pool_id = v
                            break
                    except Exception:
                        continue
        if not resolved_pool_id:
            return {"ok": False, "error": "pool_id could not be resolved from position"}
        lower, upper = self._extract_ticks_from_position(pos)
        liq = self._extract_liquidity_from_position(pos)
        # Verificar protocol position PDA con los ticks detectados (opcional)
        try:
            if lower is not None and upper is not None and resolved_pool_id:
                _proto_pos, _ = self.derive_protocol_position_pda(resolved_pool_id, int(lower), int(upper))
        except Exception:
            pass
        # Rewards (fees) acumulados si pueden inferirse del struct de posición
        rewards_a = None
        rewards_b = None
        for k in (
            "token_fees_owed_0",
            "tokenFeesOwed0",
            "tokens_owed_0",
            "tokensOwed0",
            "tokens_owed_a",
            "tokensOwedA",
            "fees_owed_a",
            "feesOwedA",
            "owed_a",
            "owedA",
        ):
            if k in pos:
                try:
                    rewards_a = int(pos[k]); break
                except Exception:
                    pass
        for k in (
            "token_fees_owed_1",
            "tokenFeesOwed1",
            "tokens_owed_1",
            "tokensOwed1",
            "tokens_owed_b",
            "tokensOwedB",
            "fees_owed_b",
            "feesOwedB",
            "owed_b",
            "owedB",
        ):
            if k in pos:
                try:
                    rewards_b = int(pos[k]); break
                except Exception:
                    pass
        return {
            "ok": True,
            "ticks": {"lower": lower, "upper": upper, "current": self.get_pool_tick_current(resolved_pool_id)},
            "liquidity": liq,
            "rewards": {"amount0": rewards_a, "amount1": rewards_b},
        }

    def positions_status(self, pool_id: Optional[str] = None, positions: Optional[List[str]] = None) -> Dict[str, Any]:
        if not positions:
            return {"ok": False, "error": "positions required"}
        out: List[Dict[str, Any]] = []
        for p in positions:
            try:
                out.append(self.position_belongs_to_pool(p, pool_id))
            except Exception as exc:
                out.append({"ok": False, "position": p, "error": str(exc)})
        return {"ok": True, "positions": out}

    def list_positions(self) -> Dict[str, Any]:
        """Lista NFTs de posición (mints) pertenecientes al owner e incluye pool_id resuelto.
        Estrategia: escanear cuentas SPL del owner (Token y Token-2022) con amount=1 y decimals=0;
        validar que exista la cuenta PersonalPosition PDA derivada del mint y leer la pool.
        """
        items: List[Dict[str, Any]] = []
        try:
            # Reutilizar RPC de wallet_state para ambos programas
            for program_id in (
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            ):
                try:
                    resp = self._rpc_call_with_failover(
                        "getTokenAccountsByOwner",
                        [
                            self.owner_pubkey,
                            {"programId": program_id},
                            {"commitment": "finalized", "encoding": "jsonParsed"},
                        ],
                    )
                    value = ((resp or {}).get("result") or {}).get("value") or []
                except Exception:
                    value = []
                for it in value:
                    try:
                        parsed = (((it or {}).get("account") or {}).get("data") or {}).get("parsed") or {}
                        info = parsed.get("info") or {}
                        mint = info.get("mint")
                        ta = info.get("tokenAmount") or {}
                        amount = ta.get("amount")
                        decimals = ta.get("decimals")
                        if not isinstance(mint, str):
                            continue
                        if not (isinstance(decimals, int) and decimals == 0):
                            continue
                        # amount puede venir como str "1"
                        try:
                            amt_i = int(amount) if isinstance(amount, str) else int(str(amount))
                        except Exception:
                            continue
                        if amt_i != 1:
                            continue
                        # Validar que el mint corresponde a una posición CLMM (existe PersonalPosition PDA)
                        try:
                            pda, _ = self._derive_personal_position_pda(mint)
                            pos_acc = self._get_account_info_base64(pda)
                            if not pos_acc:
                                continue
                            # Leer detalles para resolver pool_id
                            pool_id_resolved: Optional[str] = None
                            try:
                                pos_dec = self._read_position_core(mint)
                                for k in ("pool", "pool_id", "poolState", "pool_state", "poolId", "poolKey", "poolAddress"):
                                    if k in pos_dec:
                                        v = pos_dec[k]
                                        if isinstance(v, str) and len(v) > 0:
                                            pool_id_resolved = v
                                            break
                            except Exception:
                                pool_id_resolved = None
                            items.append({"position": mint, "pool_id": pool_id_resolved})
                        except Exception:
                            continue
                    except Exception:
                        continue
        except Exception:
            pass
        return {"ok": True, "positions": items}

    def _extract_ticks_from_position(self, pos: Dict[str, Any]) -> Tuple[Optional[int], Optional[int]]:
        lower = None
        upper = None
        if not isinstance(pos, dict):
            return lower, upper
        for k in ("tick_lower_index", "tickLowerIndex", "tick_lower", "tickLower", "lower_tick", "lowerTick"):
            if k in pos:
                try:
                    lower = int(pos[k]); break
                except Exception:
                    continue
        for k in ("tick_upper_index", "tickUpperIndex", "tick_upper", "tickUpper", "upper_tick", "upperTick"):
            if k in pos:
                try:
                    upper = int(pos[k]); break
                except Exception:
                    continue
        return lower, upper

    def _extract_liquidity_from_position(self, pos: Dict[str, Any]) -> Optional[int]:
        if not isinstance(pos, dict):
            return None
        for k in ("liquidity", "position_liquidity", "liq"):
            if k in pos:
                try:
                    return int(pos[k])
                except Exception:
                    continue
        return None

    def build_decrease_liquidity_v2_ix(
        self,
        pool_id: str,
        position_nft_mint: str,
        amount_liquidity: int,
        amount0_min: int,
        amount1_min: int,
        recipient_token_account_0: Optional[str] = None,
        recipient_token_account_1: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not pool_id:
            raise ValueError("pool_id es obligatorio")
        if not position_nft_mint:
            raise ValueError("position_nft_mint es obligatorio")
        # Estado de pool y vaults
        pool_state = self.get_pool_state_decoded(pool_id)
        vault0, vault1 = self.get_pool_vaults(pool_state)
        if not vault0 or not vault1:
            raise RuntimeError("No se pudieron determinar los vaults de la pool")
        mint0, mint1 = self.get_pool_mints(pool_state)
        # Posición
        pos = self._read_position_core(position_nft_mint)
        if not pos:
            raise RuntimeError("No se pudo leer la posición on-chain")
        person_pda = pos.get("pda") or self._derive_personal_position_pda(position_nft_mint)[0]
        # Ticks para tick arrays
        tick_lower, tick_upper = self._extract_ticks_from_position(pos)
        if tick_lower is None or tick_upper is None:
            raise RuntimeError("No fue posible extraer ticks de la posición")
        spacing = None
        for k in ("tick_spacing", "tickSpacing", "tick_spacing_index"):
            if pool_state.get(k) is not None:
                try:
                    spacing = int(pool_state.get(k)); break
                except Exception:
                    pass
        if spacing is None:
            raise RuntimeError("No se pudo determinar tickSpacing de la pool")
        start_lo = self.compute_tick_array_start_index(tick_lower, spacing)
        start_hi = self.compute_tick_array_start_index(tick_upper, spacing)
        ta_lo, _ = self.derive_tick_array_pda(pool_id, start_lo)
        ta_hi, _ = self.derive_tick_array_pda(pool_id, start_hi)
        proto_pos, _pb = self.derive_protocol_position_pda(pool_id, tick_lower, tick_upper)
        # Recipient accounts
        recv0 = recipient_token_account_0
        recv1 = recipient_token_account_1
        if not recv0:
            if self._is_sol_mint(mint0):
                try:
                    import hashlib as _hl  # type: ignore
                    from solders.pubkey import Pubkey  # type: ignore
                    seed_raw = _hl.sha256((position_nft_mint + ":wsol").encode("utf-8")).hexdigest()[:32]
                    base_pk = Pubkey.from_string(self.owner_pubkey)
                    token_prog_pk = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                    recv0 = str(Pubkey.create_with_seed(base_pk, seed_raw, token_prog_pk))
                except Exception:
                    recv0 = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
            else:
                recv0 = self._derive_ata(self.owner_pubkey, mint0)
        if not recv1:
            recv1 = self._derive_ata(self.owner_pubkey, mint1)
        # Reward accounts (por defecto, recolectar ACTIVAS): triples [vault, ATA, mint]
        reward_triples: List[Tuple[str, str, str]] = []
        rewards = []
        try:
            rewards = pool_state.get("reward_infos") or pool_state.get("rewardInfos") or []
            if isinstance(rewards, list):
                for info in rewards:
                    i = (info or {})
                    state = i.get("reward_state") or i.get("rewardState")
                    open_time = i.get("open_time") or i.get("openTime")
                    end_time = i.get("end_time") or i.get("endTime")
                    emission = i.get("emissions_per_second_x64") or i.get("emissionsPerSecondX64") or 0
                    try:
                        import time as _t  # type: ignore
                        now_ts = int(_t.time())
                        em_int = int(emission)
                        in_window = True
                        if open_time is not None and int(open_time) > 0:
                            in_window = in_window and (now_ts >= int(open_time))
                        if end_time is not None and int(end_time) > 0:
                            in_window = in_window and (now_ts <= int(end_time))
                        is_active = (str(state) == "2") or (em_int > 0 and in_window)
                    except Exception:
                        is_active = (str(state) == "2")
                    if not is_active:
                        continue
                    rmint = (i.get("reward_mint") or i.get("rewardMint") or i.get("mint") or i.get("token_mint") or i.get("tokenMint"))
                    rvault = (i.get("reward_vault") or i.get("rewardVault") or i.get("vault") or i.get("token_vault") or i.get("tokenVault") or i.get("token_vault_address"))
                    if not (isinstance(rmint, str) and isinstance(rvault, str) and rmint and rvault):
                        continue
                    rdest = self._derive_ata(self.owner_pubkey, rmint)
                    if not isinstance(rdest, str) or not rdest:
                        continue
                    reward_triples.append((rvault, rdest, rmint))
        except Exception:
            reward_triples = []

        # Asegurar número de cuentas esperado por el programa: si detectamos inconsistencia, forzar a expected_active
        try:
            expected = 0
            if isinstance(rewards, list):
                import time as _t  # type: ignore
                now_ts = int(_t.time())
                for j in rewards:
                    st = (j or {}).get("reward_state") or (j or {}).get("rewardState")
                    emis = (j or {}).get("emissions_per_second_x64") or (j or {}).get("emissionsPerSecondX64") or 0
                    try:
                        emis_i = int(emis)
                    except Exception:
                        emis_i = 0
                    # Considerar activo si emite o estado==2
                    if str(st) == "2" or emis_i > 0:
                        expected += 1
            if expected > 0 and len(reward_triples) != expected:
                forced: List[Tuple[str, str, str]] = []
                for info in (rewards or []):
                    if len(forced) >= expected:
                        break
                    i = (info or {})
                    rmint = (i.get("reward_mint") or i.get("rewardMint") or i.get("mint") or i.get("token_mint") or i.get("tokenMint"))
                    rvault = (i.get("reward_vault") or i.get("rewardVault") or i.get("vault") or i.get("token_vault") or i.get("tokenVault") or i.get("token_vault_address"))
                    if not (isinstance(rmint, str) and isinstance(rvault, str) and rmint and rvault):
                        continue
                    rdest = self._derive_ata(self.owner_pubkey, rmint)
                    if not isinstance(rdest, str) or not rdest:
                        continue
                    forced.append((rvault, rdest, rmint))
                if forced:
                    reward_triples = forced
        except Exception:
            pass
        try:
            exp_len = len(rewards) if isinstance(rewards, list) else 0
        except Exception:
            exp_len = 0
        self.logger.info(
            "decrease_liquidity_v2: rewards_len=%s triples_len=%s triples=%s",
            exp_len,
            len(reward_triples),
            " | ".join([f"{a}|{b}->{c}" for (a, b, c) in reward_triples])
        )
        # NFT token account (Token-2022)
        pos_nft_ata = self._derive_ata(self.owner_pubkey, position_nft_mint, token_program_id="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
        # Asegurar que los ATAs de rewards existen: programar creación previa si faltan
        ensure_reward_atas: List[Dict[str, Any]] = []
        for (_rvault, _rmint, rdest) in reward_triples:
            try:
                # Recuperar mint desde el vault consultando la pool si es necesario
                # Aquí ya tenemos el mint en el par derivado; no es trivial mapear
                # así que inferimos mint del ATA destino rdest si coincide la derivación
                # En su defecto, omitimos create_ata y asumimos que existe
                if not self._ata_exists(rdest):
                    # No conocemos el mint directamente aquí, así que no añadimos create_ata ciego
                    # El programa fallaría con AccountNotFound si no existe; el caller debería crearlo fuera
                    pass
            except Exception:
                continue
        # Data
        ix_name = "decrease_liquidity_v2"
        data = b"".join([
            self._anchor_discriminator(ix_name),
            self._encode_u128_le(int(amount_liquidity)),
            self._encode_u64_le(int(amount0_min)),
            self._encode_u64_le(int(amount1_min)),
        ])
        # Keys en el orden exacto esperado por el programa (evitar ambigüedad de mapeo)
        token_program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        token2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        memo_program = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        keys: List[Dict[str, Any]] = [
            {"pubkey": self.owner_pubkey, "is_signer": True, "is_writable": True},                    # nft_owner
            {"pubkey": pos_nft_ata or "", "is_signer": False, "is_writable": True},                 # nft_account (Token-2022 ATA)
            {"pubkey": person_pda, "is_signer": False, "is_writable": True},                         # personal_position
            {"pubkey": pool_id, "is_signer": False, "is_writable": True},                            # pool_state
            {"pubkey": proto_pos, "is_signer": False, "is_writable": True},                          # protocol_position
            {"pubkey": vault0, "is_signer": False, "is_writable": True},                             # token_vault_0
            {"pubkey": vault1, "is_signer": False, "is_writable": True},                             # token_vault_1
            {"pubkey": ta_lo, "is_signer": False, "is_writable": True},                               # tick_array_lower
            {"pubkey": ta_hi, "is_signer": False, "is_writable": True},                               # tick_array_upper
            {"pubkey": recv0 or "", "is_signer": False, "is_writable": True},                       # recipient_token_account_0
            {"pubkey": recv1 or "", "is_signer": False, "is_writable": True},                       # recipient_token_account_1
            {"pubkey": token_program, "is_signer": False, "is_writable": False},                      # token_program
            {"pubkey": token2022_program, "is_signer": False, "is_writable": False},                 # token_program_2022
            {"pubkey": memo_program, "is_signer": False, "is_writable": False},                      # memo_program v2
            {"pubkey": mint0 or "", "is_signer": False, "is_writable": False},                      # vault_0_mint
            {"pubkey": mint1 or "", "is_signer": False, "is_writable": False},                      # vault_1_mint
        ]
        self.logger.info(
            "decrease_liquidity_v2: base_keys=%s (hasta mints)",
            len(keys)
        )
        # Añadir reward triples [vault, ATA, mint] después de los mints base
        for (rvault, rdest, rmint) in reward_triples:
            is_placeholder = (
                str(rvault) == "11111111111111111111111111111111"
                or str(rmint) == "11111111111111111111111111111111"
                or str(rdest) == "11111111111111111111111111111111"
            )
            keys.append({"pubkey": rvault, "is_signer": False, "is_writable": (not is_placeholder)})
            keys.append({"pubkey": rdest, "is_signer": False, "is_writable": (not is_placeholder)})
            keys.append({"pubkey": rmint, "is_signer": False, "is_writable": False})
        self.logger.info(
            "decrease_liquidity_v2: total_keys=%s (incl. rewards=%s)",
            len(keys),
            len(reward_triples)
        )
        # Logging de rewards para diagnóstico
        try:
            if self.logger.isEnabledFor(logging.INFO):
                rewards_dbg = pool_state.get("reward_infos") or pool_state.get("rewardInfos") or []
                expected = 0
                if isinstance(rewards_dbg, list):
                    for j in rewards_dbg:
                        st = (j or {}).get("reward_state") or (j or {}).get("rewardState")
                        emis = (j or {}).get("emissions_per_second_x64") or (j or {}).get("emissionsPerSecondX64") or 0
                        try:
                            emis_i = int(emis)
                        except Exception:
                            emis_i = 0
                        if str(st) == "2" or emis_i > 0:
                            expected += 1
                self.logger.info(
                    "decrease_liquidity_v2: reward_triples_active=%d (expected_active~=%d) [%s]",
                    len(reward_triples), expected, ",".join([f"{a}|{b}->{c}" for (a, b, c) in reward_triples])
                )
        except Exception:
            pass
        return {
            "program_id": self.config.program_id_clmm,
            "keys": keys,
            "data": data,
            "accounts": {
                "pool": pool_id,
                "personalPosition": person_pda,
                "protocolPosition": proto_pos,
                "tickArrays": {"lower": ta_lo, "upper": ta_hi},
                "recipientTokenAccounts": {"A": recv0, "B": recv1},
                "vaults": {"A": vault0, "B": vault1},
                "positionNftMint": position_nft_mint,
                "positionNftAccount": pos_nft_ata,
                "rewardTriples": reward_triples,
            },
            "notes": [],
        }

    def collect_rewards(self, pool_id: str, position_id: str) -> Dict[str, Any]:
        """Prepara y ENVÍA on-chain la tx V0 para coleccionar fees de la posición.
        Replica el flujo de la UI: compute budget, createAccountWithSeed (WSOL), initializeAccount,
        decrease_liquidity_v2(liquidity=0), closeAccount WSOL.
        """
        # Leer estado de pool y derivados
        pos = self._read_position_core(position_id)
        if not pos:
            return {"ok": False, "error": "position not found"}
        pool_state = self.get_pool_state_decoded(pool_id)
        mint0, mint1 = self.get_pool_mints(pool_state)
        # Derivar cuentas destino
        recv0 = None
        createWithSeed: List[Dict[str, Any]] = []
        postunwrap: List[Dict[str, Any]] = []
        if self._is_sol_mint(mint0):
            # Derivar cuenta WSOL temporal por seed determinista
            try:
                import hashlib as _hl  # type: ignore
                from solders.pubkey import Pubkey  # type: ignore
                seed_raw = _hl.sha256((position_id + ":wsol").encode("utf-8")).hexdigest()[:32]
                base_pk = Pubkey.from_string(self.owner_pubkey)
                token_prog_pk = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                new_pk = Pubkey.create_with_seed(base_pk, seed_raw, token_prog_pk)
                recv0 = str(new_pk)
                # Rent estimado para token account + cerrar tras collect
                rent_lamports = 2_039_280
                createWithSeed.append({"base": self.owner_pubkey, "seed": seed_raw, "newAccount": recv0, "lamports": rent_lamports})
                postunwrap.append({"kind": "unwrap", "ata": recv0})
            except Exception:
                recv0 = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
        else:
            recv0 = self._derive_ata(self.owner_pubkey, mint0)
        recv1 = self._derive_ata(self.owner_pubkey, mint1)

        # Construir ix principal con liquidez=0
        try:
            ix_dec = self.build_decrease_liquidity_v2_ix(
                pool_id=pool_id,
                position_nft_mint=position_id,
                amount_liquidity=0,
                amount0_min=0,
                amount1_min=0,
                recipient_token_account_0=recv0,
                recipient_token_account_1=recv1,
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        # Compute budget como en la UI
        cb = {"microLamports": 25000, "units": 600000}
        anc = {"anchor": {"ix": ix_dec, "computeBudget": cb, "prewrap": [], "postunwrap": postunwrap, "createATAs": [], "createWithSeed": createWithSeed}}
        try:
            tx_b64, extras = self._assemble_v0_from_anchor(anc)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        # Enviar directamente la transacción preparada
        send_res = self.send_versioned_tx_base64(tx_b64, wait=True)
        # Intentar extraer amounts transferidos (token0/token1) desde getTransaction jsonParsed
        amounts: Dict[str, Optional[int]] = {"amount0": None, "amount1": None}
        try:
            sig = None
            if isinstance(send_res, dict):
                sig = send_res.get("signature") or ((send_res.get("confirmation") or {}).get("result") or {}).get("value")
                # Si confirmation devuelve estructura distinta, ignorar
            if isinstance(sig, str) and len(sig) > 0:
                txj = self._rpc_call_with_failover("getTransaction", [sig, {"encoding": "jsonParsed", "commitment": "confirmed"}])
                res = (txj or {}).get("result") or {}
                meta = (res.get("meta") or {})
                inner = meta.get("innerInstructions") or []
                # Calcular recipients esperados (derivados arriba)
                # Recalcular recipients para robustez
                pool_state = self.get_pool_state_decoded(pool_id)
                mint0, mint1 = self.get_pool_mints(pool_state)
                recv0_calc = None
                if self._is_sol_mint(mint0):
                    try:
                        import hashlib as _hl  # type: ignore
                        from solders.pubkey import Pubkey  # type: ignore
                        seed_raw = _hl.sha256((position_id + ":wsol").encode("utf-8")).hexdigest()[:32]
                        base_pk = Pubkey.from_string(self.owner_pubkey)
                        token_prog_pk = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                        new_pk = Pubkey.create_with_seed(base_pk, seed_raw, token_prog_pk)
                        recv0_calc = str(new_pk)
                    except Exception:
                        recv0_calc = self._derive_ata(self.owner_pubkey, self.SOL_MINT)
                else:
                    recv0_calc = self._derive_ata(self.owner_pubkey, mint0)
                recv1_calc = self._derive_ata(self.owner_pubkey, mint1)

                def _sum_amount_for_dest(dest: Optional[str]) -> Optional[int]:
                    if not isinstance(dest, str) or not dest:
                        return None
                    total = 0
                    found = False
                    for ii in inner:
                        for ins in (ii.get("instructions") or []):
                            p = ins.get("parsed") or {}
                            if (ins.get("program") == "spl-token") and isinstance(p, dict) and p.get("type") == "transferChecked":
                                info = p.get("info") or {}
                                if str(info.get("destination")) == dest:
                                    try:
                                        amt = info.get("tokenAmount", {}).get("amount") or info.get("amount")
                                        val = int(amt) if not isinstance(amt, dict) else int(amt.get("amount"))
                                        total += val
                                        found = True
                                    except Exception:
                                        continue
                    return total if found else None

                amounts["amount0"] = _sum_amount_for_dest(recv0_calc)
                amounts["amount1"] = _sum_amount_for_dest(recv1_calc)
        except Exception:
            pass

        return {
            "ok": True,
            "transactions": [tx_b64],
            "extraSigners": extras or [],
            "meta": {"poolId": pool_id, "position": position_id},
            "send": send_res,
            "result": {"amounts": amounts} if (amounts.get("amount0") is not None or amounts.get("amount1") is not None) else {},
        }

    def build_close_position_ix(self, position_nft_mint: str) -> Dict[str, Any]:
        if not position_nft_mint:
            raise ValueError("position_nft_mint es obligatorio")
        pos = self._read_position_core(position_nft_mint)
        if not pos:
            raise RuntimeError("No se pudo leer la posición on-chain")
        person_pda = pos.get("pda") or self._derive_personal_position_pda(position_nft_mint)[0]
        pos_nft_ata = self._derive_ata(self.owner_pubkey, position_nft_mint, token_program_id="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
        ix_name = "close_position"
        data = self._anchor_discriminator(ix_name)
        # Keys explícitas en orden
        keys: List[Dict[str, Any]] = [
            {"pubkey": self.owner_pubkey, "is_signer": True, "is_writable": True},                    # nft_owner
            {"pubkey": position_nft_mint, "is_signer": False, "is_writable": True},                   # position_nft_mint (Token-2022 Mint)
            {"pubkey": pos_nft_ata or "", "is_signer": False, "is_writable": True},                 # position_nft_account (ATA 2022)
            {"pubkey": person_pda, "is_signer": False, "is_writable": True},                          # personal_position
            {"pubkey": "11111111111111111111111111111111", "is_signer": False, "is_writable": False}, # system_program
            {"pubkey": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "is_signer": False, "is_writable": False}, # token_2022
        ]
        return {
            "program_id": self.config.program_id_clmm,
            "keys": keys,
            "data": data,
            "accounts": {
                "personalPosition": person_pda,
                "positionNftMint": position_nft_mint,
                "positionNftAccount": pos_nft_ata,
            },
            "notes": [],
        }

    def liquidity_prepare_remove(
        self,
        position_nft_mint: str,
        pool_id: Optional[str],
        slippage_bps: int = 0,
        compute_unit_price_micro: int = 25_000,
        compute_unit_limit: int = 600_000,
    ) -> Dict[str, Any]:
        # Leer posición y pool
        pos = self._read_position_core(position_nft_mint)
        if not pos:
            return {"canSend": False, "error": "position not found", "notes": ["No se pudo leer la posición on-chain"]}
        pool = pool_id or pos.get("pool_id")
        if not isinstance(pool, str) or not pool:
            return {"canSend": False, "error": "pool id missing", "notes": ["Falta pool_id"]}
        # Liquidez a remover: por defecto 100%
        liq = self._extract_liquidity_from_position(pos)
        if liq is None:
            return {"canSend": False, "error": "liquidity missing", "notes": ["No se pudo extraer liquidity de la posición"]}
        # Mínimos: por simplicidad, 0
        a_min = 0
        b_min = 0
        # Destinatarios: cuenta WSOL temporal con seed + ATA USDC del owner
        pool_state = self.get_pool_state_decoded(pool)
        mint0, mint1 = self.get_pool_mints(pool_state)
        # Derivar cuenta WSOL temporal (no ATA) con seed determinista
        recv0 = None
        wsol_seed = None
        wsol_new_account = None
        if self._is_sol_mint(mint0):
            import hashlib
            seed_raw = hashlib.sha256((position_nft_mint + ":wsol").encode("utf-8")).hexdigest()[:32]
            wsol_seed = seed_raw
            # Derivar la dirección exacta con create_with_seed(base=owner, seed, owner=Token Program)
            try:
                from solders.pubkey import Pubkey  # type: ignore
                base_pk = Pubkey.from_string(self.owner_pubkey)
                token_prog_pk = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                new_pk = Pubkey.create_with_seed(base_pk, wsol_seed, token_prog_pk)
                recv0 = str(new_pk)
            except Exception:
                # Si no podemos derivarla aquí, mantenemos None para forzar error explícito
                recv0 = None
        recv1 = self._derive_ata(self.owner_pubkey, mint1)
        # Planear unwrap post para WSOL temporal
        prewrap: List[Dict[str, Any]] = []
        postunwrap: List[Dict[str, Any]] = []
        createATAs: List[Dict[str, Any]] = []
        createWithSeed: List[Dict[str, Any]] = []
        if self._is_sol_mint(mint0) and wsol_seed and isinstance(recv0, str) and len(recv0) > 0:
            # Estimación mínima de rent para una cuenta de token (165 bytes) + margen
            rent_lamports = 2_039_280  # aproximado, actualizado por RPC si se quiere
            createWithSeed.append({
                "base": self.owner_pubkey,
                "seed": wsol_seed,
                "newAccount": recv0,
                "lamports": rent_lamports,
            })
            postunwrap.append({"kind": "unwrap", "ata": recv0})
        # Construir ix decrease
        try:
            ix_dec = self.build_decrease_liquidity_v2_ix(
                pool_id=pool,
                position_nft_mint=position_nft_mint,
                amount_liquidity=int(liq),
                amount0_min=int(a_min),
                amount1_min=int(b_min),
                recipient_token_account_0=recv0,
                recipient_token_account_1=recv1,
            )
        except Exception as exc:
            return {"canSend": False, "error": str(exc), "notes": [str(exc)]}
        cb = {"microLamports": int(compute_unit_price_micro), "units": int(compute_unit_limit)}
        anc_dec = {"anchor": {"ix": ix_dec, "computeBudget": cb, "prewrap": prewrap, "postunwrap": postunwrap, "createATAs": createATAs, "createWithSeed": createWithSeed}}
        # Añadir close_position como extraIxs en la misma transacción que decrease
        try:
            ix_close = self.build_close_position_ix(position_nft_mint)
        except Exception as exc2:
            return {"canSend": False, "error": str(exc2), "notes": [str(exc2)]}
        anc_dec["anchor"]["extraIxs"] = [ix_close]
        # Crear ATAs para rewards si no existen
        try:
            rtrip = ((ix_dec.get("accounts") or {}).get("rewardTriples") or [])
            for (_rvault, rdest, rmint) in rtrip:
                try:
                    if isinstance(rmint, str) and self._ata_exists(rdest) is False:
                        createATAs.append({"owner": self.owner_pubkey, "mint": rmint})
                except Exception:
                    continue
        except Exception:
            pass
        tx1_b64, extras1 = self._assemble_v0_from_anchor(anc_dec)
        return {
            "canSend": True,
            "transactions": [tx1_b64],
            "extraSigners": extras1 or [],
            "meta": {"poolId": pool, "position": position_nft_mint},
            "notes": [],
        }

__all__ = ["RaydiumAdapter", "RaydiumConfig"]


