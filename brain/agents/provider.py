from __future__ import annotations

from typing import Dict, Any, Optional
import os


def get_model_settings(brain_cfg: Dict[str, Any]) -> Dict[str, Any]:
    models = (brain_cfg or {}).get("models") or {}
    provider = str(models.get("provider") or "").lower()
    name = models.get("name")
    if not name:
        return {}
    # Ajustes mínimos: permitir indicar provider/endpoint por variables de entorno si aplica
    if provider == "ollama":
        # Si se usa LiteLLM sobre Ollama, puede requerir un endpoint; no forzamos defaults, sólo honramos env si existe
        base = os.getenv("OLLAMA_BASE_URL")
        return {"model": name, "base_url": base} if base else {"model": name}
    return {"model": name}


