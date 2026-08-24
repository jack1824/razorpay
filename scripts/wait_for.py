"""Block until PostgreSQL accepts a connection, or time out.

Compose healthchecks cover the container being up; this covers the database being ready to
accept the migration connection, which is a different moment.
"""

from __future__ import annotations

import sys
import time

import psycopg


def wait(dsn: str, timeout_s: float = 60.0, interval_s: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(interval_s)
    print(f"timed out waiting for {dsn.split('@')[-1]}: {last}", file=sys.stderr)
    return False


if __name__ == "__main__":
    dsn = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
    raise SystemExit(0 if wait(dsn, timeout) else 1)
