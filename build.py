#!/usr/bin/env python3
"""Build a standalone, readable Bash/Python script from the two source modules."""
import hashlib
import argparse
from pathlib import Path

root = Path(__file__).resolve().parent
core = (root / "src/netcheck.py").read_text(encoding="utf-8")
repair = (root / "src/netcheck_repair.py").read_text(encoding="utf-8")
header = '''#!/usr/bin/env bash
# VPS Netcheck 2.0.0-rc1. Sources and tests are in the accompanying release.
# Requires Python 3.8+. This launcher does not install dependencies.
set -u
command -v python3 >/dev/null 2>&1 || { echo '需要 Python 3.8+；请先安装 python3。' >&2; exit 2; }
exec python3 - "$@" <<'VPS_NETCHECK_PYTHON_EOF'
import sys
if sys.version_info < (3, 8):
    sys.exit('需要 Python 3.8+')
import types
_repair = types.ModuleType('netcheck_repair')
'''
# repr is Python source quoting, not shell interpolation. The here-doc is quoted.
payload = header + "_repair.REPAIR_SOURCE = " + repr(repair) + "\n"
payload += "exec(compile(_repair.REPAIR_SOURCE, '<netcheck_repair>', 'exec'), _repair.__dict__)\n"
payload += "sys.modules['netcheck_repair'] = _repair\n\n" + core + "\nVPS_NETCHECK_PYTHON_EOF\n"
target = root / "vps-netcheck-v2.sh"
script_bytes = payload.encode("utf-8")
checksum_bytes = (hashlib.sha256(script_bytes).hexdigest() + "  " + target.name + "\n").encode("ascii")
parser = argparse.ArgumentParser(description="构建 v2 单文件及校验和；--check 只检查是否与源码一致")
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
artifacts = {target: script_bytes, root / "SHA256SUMS": checksum_bytes}
if args.check:
    stale = [p.name for p, data in artifacts.items() if not p.exists() or p.read_bytes() != data]
    if stale:
        parser.exit(1, "构建产物与源码不一致，请运行 python3 build.py：" + ", ".join(stale) + "\n")
    print("构建产物与源码一致")
else:
    for path, data in artifacts.items():
        path.write_bytes(data)
    print(target)
