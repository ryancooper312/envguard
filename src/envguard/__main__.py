"""支持 python3 -m envguard 直接运行 CLI。"""

from envguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
