from __future__ import annotations

import argparse

from .server import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the service SLA settlement API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--database", default="var/service-sla.db")
    args = parser.parse_args()
    serve(args.host, args.port, args.database)


if __name__ == "__main__":
    main()

