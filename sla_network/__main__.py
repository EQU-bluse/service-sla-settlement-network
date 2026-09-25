from __future__ import annotations

import argparse
import re

from .server import serve

# 仲裁机器标识与机器 id 同形：SHA-256 公钥的小写十六进制。
ARBITRATOR_PATTERN = re.compile(r"[0-9a-f]{64}")


def _arbitrator(value: str) -> str:
    # 格式非法由 argparse 统一报错并以退出码 2 结束。
    if ARBITRATOR_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("invalid arbitrator machine id")
    return value


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the service SLA settlement API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--database", default="var/service-sla.db")
    parser.add_argument("--arbitrator", default=None, type=_arbitrator)
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.database, args.arbitrator)


if __name__ == "__main__":
    main()
