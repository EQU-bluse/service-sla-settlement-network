from __future__ import annotations

import argparse
import re

from .server import serve

# --arbitrator 机器标识须为机器 id 形式（sha256 公钥的小写十六进制）。
ARBITRATOR_PATTERN = re.compile(r"[0-9a-f]{64}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the service SLA settlement API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--database", default="var/service-sla.db")
    parser.add_argument(
        "--arbitrator",
        action="append",
        default=[],
        metavar="MACHINE_ID",
        help="machine authorized to arbitrate escalated disputes (repeatable)",
    )
    args = parser.parse_args()
    for arbitrator in args.arbitrator:
        if ARBITRATOR_PATTERN.fullmatch(arbitrator) is None:
            # 格式非法：argparse 报错并以退出码 2 终止，服务不启动。
            parser.error(f"invalid --arbitrator machine id: {arbitrator!r}")
    serve(args.host, args.port, args.database, args.arbitrator)


if __name__ == "__main__":
    main()
