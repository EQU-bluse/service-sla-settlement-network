from __future__ import annotations

import argparse
import re

from .server import serve

# --arbitrator / --auditor 机器标识须为机器 id 形式（sha256 公钥的小写十六进制）。
MACHINE_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


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
    parser.add_argument(
        "--auditor",
        action="append",
        default=[],
        metavar="MACHINE_ID",
        help="machine authorized to create and read audit checkpoints (repeatable)",
    )
    args = parser.parse_args()
    for arbitrator in args.arbitrator:
        if MACHINE_ID_PATTERN.fullmatch(arbitrator) is None:
            # 格式非法：argparse 报错并以退出码 2 终止，服务不启动。
            parser.error(f"invalid --arbitrator machine id: {arbitrator!r}")
    for auditor in args.auditor:
        if MACHINE_ID_PATTERN.fullmatch(auditor) is None:
            # 格式非法：argparse 报错并以退出码 2 终止，服务不启动。
            parser.error(f"invalid --auditor machine id: {auditor!r}")
    serve(args.host, args.port, args.database, args.arbitrator, args.auditor)


if __name__ == "__main__":
    main()
