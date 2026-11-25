"""envguard 命令行入口，支持文本与 JSON 两种结果输出格式。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from envguard.parser import parse_env_file
from envguard.validator import validate_env


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="Validate .env against .env.example schemas and scan for template secret leaks.",
    )
    parser.add_argument("--env", default=".env", help="Path to target .env file (default: .env)")
    parser.add_argument(
        "--example",
        default=".env.example",
        help="Path to schema template file (default: .env.example)",
    )
    parser.add_argument(
        "--allow-extra",
        action="store_true",
        help="Allow keys in .env that are not declared in .env.example",
    )
    parser.add_argument(
        "--no-secret-scan",
        action="store_true",
        help="Disable scanning .env.example for real secret patterns",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit validation report as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """解析 CLI 参数并执行校验，返回标准进程退出码。"""
    args = build_parser().parse_args(argv)
    env_path = Path(args.env)
    example_path = Path(args.example)

    for label, path in (("--env", env_path), ("--example", example_path)):
        if not path.is_file():
            msg = f"error: {label} file not found: {path}"
            if args.json_output:
                print(json.dumps({"ok": False, "error": msg}))
            else:
                print(msg, file=sys.stderr)
            return 2

    env_entries = parse_env_file(env_path)
    example_entries = parse_env_file(example_path)
    report = validate_env(
        env_entries,
        example_entries,
        allow_extra=args.allow_extra,
        scan_secrets=not args.no_secret_scan,
    )

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        if report.ok:
            print(f"OK: validated {report.checked_keys} keys with 0 issues.")
        else:
            for item in report.findings:
                print(f"[{item.code}] {item.message}", file=sys.stderr)
            print(
                f"FAILED: {len(report.findings)} issue(s) across {report.checked_keys} declared keys.",
                file=sys.stderr,
            )

    return 0 if report.ok else 1
