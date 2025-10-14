RaydiumAdapter (CLMM) - Guía rápida

Requisitos
- Python 3.10+
- solders, solana-py, httpx/requests, pyyaml, logging
- .env con `LOG_LEVEL` (e.g. INFO)
- Configuración en `adapters/Raydium/config/solana.raydium.yaml` (RPC/WSS/clave/CLMM program)

Configuración
- No uses .env para RPCs; se leen de YAML para mantener agnosticidad por cadena [[memory:8739059]].
- Edita `solana.raydium.yaml` para:
  - `solana.rpc_endpoints` / `wss_endpoints`
  - `solana.keypair_path`
  - `raydium.program_id_clmm`, `raydium.api_base`, `priority_fee_tier`
  - `raydium.defaults`: `slippage_bps`, `compute_unit_*` y `pool_ids`

Flujo de provisión (prepare + send)
1) Cargar adapter y pool
2) Calcular rango de ticks y cantidades deseadas
3) `liquidity_quote_by_ticks` para construir quote
4) `liquidity_prepare(quote)` genera:
   - Ix Anchor `open_position_with_token22_nft`
   - ComputeBudget ixs
   - WSOL: create ATA (si falta) + transfer SOL + syncNative + closeAccount
5) `liquidity_send(prep)` firma y envía la tx v0.

Notas de WSOL y slippage
- El adapter inserta automáticamente `transfer` + `syncNative` antes del ix Anchor cuando uno de los mints es SOL.
- El monto de wrap se toma del payload Anchor real (amount_0_max/1), garantizando que `transferChecked` no falle por fondos.
- Además del `slippage_bps` del usuario, se añade un buffer interno de +100 bps a `amount*_max` para robustez ante microcambios.

Ejemplo mínimo (notebook)
- Ver `notebooks/notebook.ipynb` con el flujo 50/50 WSOL/USDC en la pool `sol_usdc` del YAML.

Logs
- Controla el nivel con `LOG_LEVEL` en `.env`. El adapter emite pasos clave: compute budget, wrap/sync, datos Anchor y envío.

Advertencias
- El usuario gestiona Git (commits/push). No ejecutes comandos Git desde el adapter [[memory:8635374]].

