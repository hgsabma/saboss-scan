"""Command line for the Saboss platform.

python -m saboss_platform serve     start the web app (http://127.0.0.1:8000)
python -m saboss_platform migrate   apply database migrations only
"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m saboss_platform")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the web application")
    serve.add_argument("--host", default=os.environ.get("SABOSS_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("SABOSS_PORT", "8000")))
    serve.add_argument("--reload", action="store_true", help="Restart on code changes (development)")
    commands.add_parser("migrate", help="Apply database migrations")
    args = parser.parse_args(argv)

    if args.command == "migrate":
        from .config import get_settings
        from .db import run_migrations

        run_migrations(get_settings().database_url)
        print("Database is up to date.")
        return 0

    import uvicorn

    uvicorn.run(
        "saboss_platform.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("SABOSS_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        server_header=False,
        access_log=False,  # requests are logged by the app as JSON
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
