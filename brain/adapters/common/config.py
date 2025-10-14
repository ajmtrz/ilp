import os
import logging
from typing import Optional

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore


def get_project_root(start_file: Optional[str] = None) -> str:
    """Descubre la raíz del proyecto.
    Preferencias (en orden):
      1) Directorio que contenga 'brain' (por ejemplo, '/.../ild')
      2) Directorio que contenga '.git'
      3) Si estamos dentro de '.../brain', devolver su padre
      4) Fallback: tres niveles arriba
    """
    path = os.path.abspath(start_file or __file__)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    cur = path
    while True:
        # Caso 1: encontramos el contenedor de 'brain'
        if os.path.isdir(os.path.join(cur, "brain")):
            return cur
        # Caso 2: repo raíz por '.git'
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        # Caso 3: si estamos exactamente en '.../brain', devolver el padre
        if os.path.basename(cur) == "brain":
            return os.path.dirname(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            # Fallback conservador: subir tres niveles desde path inicial
            return os.path.abspath(os.path.join(path, "..", "..", ".."))
        cur = parent


def load_project_env(project_root: str) -> None:
    """Carga variables de entorno buscando .env desde project_root hacia arriba.
    Orden de búsqueda: project_root/.env, parent/.env, grandparent/.env, great-grandparent/.env.
    """
    if load_dotenv is None:
        return
    candidates = []
    cur = os.path.abspath(project_root)
    for _ in range(4):  # project_root y hasta 3 niveles arriba
        candidates.append(os.path.join(cur, ".env"))
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    for env_path in candidates:
        if os.path.exists(env_path):
            load_dotenv(dotenv_path=env_path)
            break


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


