"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store an input and its start time until the output is available."""
        normalized_user_id = user_id or "anonymous"
        key = request_id or normalized_user_id
        self._open[key] = {
            "request_id": request_id,
            "user_id": normalized_user_id,
            "input": text or "",
            "started_at": utc_now_iso(),
            "started_monotonic": time.perf_counter(),
        }
        return key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete an interaction and append a forensic audit record."""
        normalized_user_id = user_id or "anonymous"
        key = request_id or normalized_user_id
        pending = self._open.pop(key, None)

        # Keep an output record even if its matching input was unavailable. This
        # is preferable to silently losing evidence during incident review.
        if pending is None:
            pending = {
                "request_id": request_id,
                "user_id": normalized_user_id,
                "input": "",
                "started_at": utc_now_iso(),
                "started_monotonic": time.perf_counter(),
            }

        latency_ms = max(
            0.0,
            (time.perf_counter() - pending["started_monotonic"]) * 1000,
        )
        record = {
            "request_id": pending["request_id"],
            "user_id": pending["user_id"],
            "input": pending["input"],
            "output": text or "",
            "blocked": bool(blocked),
            "layer": layer,
            "started_at": pending["started_at"],
            "completed_at": utc_now_iso(),
            "latency_ms": round(latency_ms, 3),
        }
        self.logs.append(record)
        return record

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
