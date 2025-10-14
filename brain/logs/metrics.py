from __future__ import annotations

from typing import Dict, Any, List
import time
import logging


class Metrics:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("metrics")

    def record(self, name: str, fields: Dict[str, Any]) -> None:
        evt = {"t": time.time(), "name": name, **(fields or {})}
        self.events.append(evt)
        try:
            self.logger.info("metric %s %s", name, fields)
        except Exception:
            pass


