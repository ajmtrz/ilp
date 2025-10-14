from __future__ import annotations

from typing import Callable, Dict, Any


class ToolRegistry:
    """Registro simple de herramientas por nombre, agnóstico al protocolo.
    Cada herramienta es una función que recibe un dict validado y devuelve dict/ToolResult.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, Callable[[dict], Any]] = {}

    def register(self, name: str, fn: Callable[[dict], Any]) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("tool name inválido")
        if not callable(fn):
            raise ValueError("tool debe ser callable")
        self._tools[name] = fn

    def get(self, name: str) -> Callable[[dict], Any]:
        if name not in self._tools:
            raise KeyError(f"tool no registrada: {name}")
        return self._tools[name]

    def list(self) -> Dict[str, Callable[[dict], Any]]:
        return dict(self._tools)


