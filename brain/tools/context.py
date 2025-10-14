from __future__ import annotations

from typing import Any, Dict
import logging


class ToolContext:
    def __init__(self, runtime: Dict[str, Any]) -> None:
        self.runtime = dict(runtime or {})
        self.logger = logging.getLogger("ToolContext")

    @property
    def config(self) -> Dict[str, Any]:
        return self.runtime.get("config") or {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.runtime.get(key, default)


