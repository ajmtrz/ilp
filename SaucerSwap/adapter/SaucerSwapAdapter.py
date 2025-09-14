import os
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List
from dotenv import load_dotenv
import yaml


@dataclass
class SaucerSwapConfig:
    network: str
    private_key_path: str
    api_base: str


class SaucerSwapAdapter:
    def __init__(self, config_path: str):
        root_env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", ".env")
        load_dotenv(dotenv_path=os.path.abspath(root_env))
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, log_level_str, logging.INFO)
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
        self.logger = logging.getLogger(self.__class__.__name__)

        self.api_key = os.getenv("SAUCER_API")
        if not self.api_key:
            raise RuntimeError("SAUCER_API no configurada en .env")

        config_path_abs = os.path.abspath(config_path)
        with open(config_path_abs, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        hed = cfg["hedera"]
        ssw = cfg["saucerswap"]
        self.config = SaucerSwapConfig(
            network=hed["network"],
            private_key_path=(hed.get("wallet") or {})["private_key_path"],
            api_base=ssw["api_base"],
        )

        expanded = os.path.expanduser(self.config.private_key_path)
        with open(expanded, "r", encoding="utf-8") as f:
            key_json = json.load(f)
        self.account_id = key_json["account_id"]
        if not isinstance(self.account_id, str) or not self.account_id:
            raise ValueError("account_id ausente o inválido en el archivo de clave")

        self.logger.info("SaucerSwapAdapter inicializado (network=%s, account_id=%s)", self.config.network, self.account_id)

    def _saucerswap_positions(self, account_id: str) -> List[Dict[str, Any]]:
        import requests
        api_url = self.config.api_base.rstrip("/") + f"/v2/nfts/{account_id}/positions"
        headers = {
            "x-api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "LiquidityProvider/1.0",
        }
        r = requests.get(api_url, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def _saucerswap_pools(self) -> List[Dict[str, Any]]:
        """
        Obtiene todas las pools disponibles de SaucerSwap.
        
        Returns:
            Lista de pools con información completa incluyendo tickCurrent
        """
        import requests
        api_url = self.config.api_base.rstrip("/") + "/v2/pools"
        headers = {
            "x-api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "LiquidityProvider/1.0",
        }
        try:
            r = requests.get(api_url, headers=headers, timeout=20)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
        except Exception as exc:
            self.logger.error(f"Error obteniendo pools de SaucerSwap: {exc}")
            return []

    def _find_pool_by_tokens_and_fee(self, token0_id: str, token1_id: str, fee: int) -> Dict[str, Any]:
        """
        Encuentra una pool específica basándose en los IDs de los tokens y el fee.
        
        Args:
            token0_id: ID del token0 (ej: "0.0.456858")
            token1_id: ID del token1 (ej: "0.0.1456986") 
            fee: Fee de la pool (ej: 1500)
            
        Returns:
            Diccionario con la información de la pool encontrada o diccionario vacío
        """
        pools = self._saucerswap_pools()
        
        for pool in pools:
            try:
                # Verificar si los tokens coinciden (en cualquier orden) y el fee
                token_a_id = pool.get("tokenA", {}).get("id")
                token_b_id = pool.get("tokenB", {}).get("id")
                pool_fee = pool.get("fee")
                
                if (pool_fee == fee and 
                    ((token_a_id == token0_id and token_b_id == token1_id) or
                     (token_a_id == token1_id and token_b_id == token0_id))):
                    return pool
                    
            except Exception as exc:
                self.logger.warning(f"Error procesando pool: {exc}")
                continue
                
        self.logger.warning(f"No se encontró pool para tokens {token0_id}/{token1_id} con fee {fee}")
        return {}

    def _strip_fields(self, pos: Dict[str, Any]) -> Dict[str, Any]:
        # Crea una copia superficial y elimina 'description' en token0/token1 si existen
        cleaned = dict(pos)
        for key in ("token0", "token1"):
            tok = cleaned.get(key)
            if isinstance(tok, dict) and "description" in tok:
                tok = dict(tok)
                tok.pop("description", None)
                cleaned[key] = tok
            if isinstance(tok, dict) and "icon" in tok:
                tok = dict(tok)
                tok.pop("icon", None)
                cleaned[key] = tok
            if isinstance(tok, dict) and "website" in tok:
                tok = dict(tok)
                tok.pop("website", None)
                cleaned[key] = tok
        return cleaned

    def check_position_exists_tool(self, serial: int) -> Dict[str, Any]:
        """
        Comprueba si existe una posición de SaucerSwap V2 (Hedera) para el account_id (leído del keyfile) y el serial del NFT.
        Incluye el tickCurrent de la pool correspondiente.

        Parámetros:
        - serial: entero del serial del NFT

        Devuelve:
        { "exists": bool, "details": ApiNftPositionV2 | {} }
        """
        if serial is None:
            return {"exists": False, "details": {"reason": "missing serial"}}
        try:
            positions = self._saucerswap_positions(self.account_id)
        except Exception as exc:
            return {"exists": False, "details": {"error": f"saucerswap api failed: {exc}"}}
        
        for pos in positions:
            try:
                if int(pos.get("tokenSN")) == int(serial):
                    # Obtener información de la pool para incluir tickCurrent
                    token0_id = pos.get("token0", {}).get("id")
                    token1_id = pos.get("token1", {}).get("id")
                    fee = pos.get("fee")
                    
                    pool_info = {}
                    if token0_id and token1_id and fee is not None:
                        pool_info = self._find_pool_by_tokens_and_fee(token0_id, token1_id, fee)
                    
                    # Crear la respuesta con los datos de la posición
                    position_details = self._strip_fields(pos)
                    
                    # Agregar tickCurrent si se encontró la pool
                    if pool_info:
                        position_details["tickCurrent"] = pool_info.get("tickCurrent")
                        self.logger.info(f"Pool encontrada: ID={pool_info.get('id')}, tickCurrent={pool_info.get('tickCurrent')}")
                    else:
                        self.logger.warning(f"No se pudo encontrar información de la pool para la posición {serial}")
                    
                    return {"exists": True, "details": position_details}
            except Exception as exc:
                self.logger.warning(f"Error procesando posición {serial}: {exc}")
                continue
        return {"exists": False, "details": {}}


__all__ = ["SaucerSwapAdapter", "SaucerSwapConfig"]
