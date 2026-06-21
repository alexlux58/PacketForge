from __future__ import annotations

from packetforge.engine.environment import ensure_supported_python


def main() -> int:
    ensure_supported_python()
    from packetforge.app import run

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
