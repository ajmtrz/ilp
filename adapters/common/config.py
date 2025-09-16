import os
import logging
from typing import Optional

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore


def get_project_root(start_file: Optional[str] = None) -> str:
    """Descubre la raíz del proyecto buscando un directorio que contenga '.git' o 'adapters'.
    Parte desde el archivo indicado (o este módulo) y asciende hasta '/' o hasta encontrar la raíz.
    """
    path = os.path.abspath(start_file or __file__)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    cur = path
    while True:
        git_dir = os.path.join(cur, ".git")
        adapters_dir = os.path.join(cur, "adapters")
        if os.path.isdir(git_dir) or os.path.isdir(adapters_dir):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            # fallback: tres niveles arriba por estructura conocida
            return os.path.abspath(os.path.join(path, "..", "..", ".."))
        cur = parent


def load_project_env(project_root: str) -> None:
    """Carga variables de entorno desde project_root/.env si python-dotenv está disponible."""
    if load_dotenv is None:
        return
    env_path = os.path.join(project_root, ".env")
    if os.path.exists(env_path):
        load_dotenv(dotenv_path=env_path)


def configure_logging() -> None:
    """Configura logging utilizando exclusivamente LOG_LEVEL del entorno (.env).
    No reconfigura si ya hay handlers.
    """
    if logging.getLogger().handlers:
        # ya configurado por el ejecutor (e.g., Jupyter)
        return
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")


def resolve_from_root(project_root: str, relative_path: str) -> str:
    """Resuelve una ruta relativa respecto a la raíz del proyecto."""
    if os.path.isabs(relative_path):
        return relative_path
    return os.path.abspath(os.path.join(project_root, relative_path))


__all__ = [
    "get_project_root",
    "load_project_env",
    "configure_logging",
    "resolve_from_root",
]


