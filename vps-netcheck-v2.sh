#!/usr/bin/env bash
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
_repair.REPAIR_SOURCE = '"""Explicit reversible repairs. All persistent actions are guarded by a systemd timer."""\nimport argparse\nimport base64\nimport contextlib\nimport hashlib\nimport ipaddress\nimport json\nimport os\nimport re\nimport shutil\nimport subprocess\nimport sys\nimport time\nfrom pathlib import Path\n\nSTATE_ROOT = Path("/var/lib/vps-netcheck")\n\n\ndef command(argv, check=True):\n    r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,\n                       encoding="utf-8", errors="replace", timeout=20, env=dict(os.environ, LC_ALL="C"))\n    if check and r.returncode:\n        raise RuntimeError("%s: %s" % (argv[0], r.stderr.strip()))\n    return r\n\n\ndef atomic_write(path, data, mode=0o600):\n    temp = path.with_name(path.name + ".new-" + os.urandom(4).hex())\n    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)\n    try:\n        with os.fdopen(fd, "wb") as f:\n            f.write(data); f.flush(); os.fsync(f.fileno())\n        os.replace(temp, path)\n    finally:\n        if temp.exists(): temp.unlink()\n\n\ndef snapshot_file(path):\n    p = Path(path)\n    if p.is_symlink():\n        raise RuntimeError("拒绝直接修改符号链接：%s；请通过系统网络管理器配置" % path)\n    if not p.exists():\n        return {"path": path, "exists": False, "data": None}\n    st = p.stat()\n    if not p.is_file(): raise RuntimeError("目标不是普通文件")\n    return {"path": path, "exists": True, "data": base64.b64encode(p.read_bytes()).decode(),\n            "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid}\n\n\ndef restore_file(item):\n    p = Path(item["path"])\n    if p.is_symlink(): raise RuntimeError("回滚时文件变成符号链接，拒绝覆盖：" + str(p))\n    if item["exists"]:\n        atomic_write(p, base64.b64decode(item["data"]), item["mode"])\n        os.chown(p, item["uid"], item["gid"])\n    elif p.exists():\n        p.unlink()\n\n\ndef choose_iface(explicit):\n    if explicit:\n        if not Path("/sys/class/net", explicit).exists(): raise RuntimeError("网卡不存在")\n        return explicit\n    r = command(["ip", "-j", "route", "get", "1.1.1.1"])\n    rows = json.loads(r.stdout)\n    if not rows or not rows[0].get("dev"): raise RuntimeError("无法确定接口，请指定 --interface")\n    return rows[0]["dev"]\n\n\ndef build_plan(args):\n    action = args.repair\n    plan = {"action": action, "files": [], "operations": [], "scope": "", "rollback_seconds": args.rollback_after}\n    if action == "mtu":\n        if not args.value or not re.fullmatch(r"[0-9]{3,5}", args.value):\n            raise RuntimeError("MTU 必须显式指定 --value")\n        mtu = int(args.value)\n        if not 1280 <= mtu <= 9000: raise RuntimeError("本版 MTU 安全范围为 1280..9000")\n        iface = choose_iface(args.interface)\n        old = int(Path("/sys/class/net", iface, "mtu").read_text())\n        plan.update(interface=iface, before_mtu=old, after_mtu=mtu,\n                    scope="仅当前接口运行时 MTU；不写开机服务，不覆盖网络管理器配置")\n        plan["operations"] = [["ip", "link", "set", "dev", iface, "mtu", str(mtu)]]\n    elif action == "dns":\n        if not args.value: raise RuntimeError("DNS 必须显式指定 --value IP[,IP]")\n        ips = [str(ipaddress.ip_address(x.strip())) for x in args.value.split(",")]\n        if not 1 <= len(ips) <= 3: raise RuntimeError("DNS 数量需为 1..3")\n        snap = snapshot_file("/etc/resolv.conf")\n        old = base64.b64decode(snap["data"]).decode("utf-8", "replace") if snap["data"] else ""\n        if re.search(r"generated|managed|resolvconf|NetworkManager|systemd", old, re.I):\n            raise RuntimeError("resolv.conf 标注为自动管理，本版不覆盖；请通过对应网络管理器配置")\n        # A plain resolv.conf can still be managed. Reject active managers as well.\n        for unit in ("NetworkManager", "systemd-resolved", "systemd-networkd"):\n            if command(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0:\n                raise RuntimeError("检测到活动网络管理器 %s，本版不直接改 DNS" % unit)\n        retained = [line for line in old.splitlines() if not re.match(r"\\s*nameserver\\s", line)]\n        new = "\\n".join(retained + ["nameserver " + x for x in ips]) + "\\n"\n        plan["files"] = [dict(snap, after=base64.b64encode(new.encode()).decode())]\n        plan.update(dns=ips, scope="静态 /etc/resolv.conf；保留 search/options 等其他配置")\n    elif action == "ipv4-prefer":\n        snap = snapshot_file("/etc/gai.conf")\n        old = base64.b64decode(snap["data"]).decode("utf-8") if snap["data"] else ""\n        if re.search(r"^\\s*(precedence|label)\\s", old, re.M):\n            raise RuntimeError("已有自定义 gai 策略，拒绝覆盖；请手工合并")\n        addition = "\\n# vps-netcheck managed policy\\nprecedence ::1/128 50\\nprecedence ::/0 40\\nprecedence 2002::/16 30\\nprecedence ::/96 20\\nprecedence ::ffff:0:0/96 100\\n"\n        plan["files"] = [dict(snap, after=base64.b64encode((old + addition).encode()).decode())]\n        plan["scope"] = "glibc getaddrinfo 地址排序；不保证其他 DNS 实现及已有进程缓存立即变化"\n    elif action == "mss":\n        if not shutil.which("iptables"): raise RuntimeError("缺少 iptables；不会自动安装")\n        plan["scope"] = "IPv4 OUTPUT/FORWARD 的运行时规则；每条使用事务专属 comment，不持久化"\n    elif action in ("ntp", "flush-dns"):\n        plan["scope"] = "启用已有 NTP 服务" if action == "ntp" else "刷新 systemd-resolved 缓存（无可恢复前态）"\n        if action == "ntp":\n            old = command(["timedatectl", "show", "-p", "NTP", "--value"]).stdout.strip()\n            if old not in ("yes", "no"): raise RuntimeError("无法读取 NTP 原状态")\n            plan["before_ntp"] = old\n            plan["operations"] = [["timedatectl", "set-ntp", "true"]]\n        else:\n            if not shutil.which("resolvectl"): raise RuntimeError("未发现 resolvectl，不推断有无其他缓存")\n            plan["operations"] = [["resolvectl", "flush-caches"]]\n    return plan\n\n\ndef verify_plan(plan):\n    for item in plan["files"]:\n        p = Path(item["path"])\n        if p.is_symlink() or not p.exists() or p.read_bytes() != base64.b64decode(item["after"]):\n            raise RuntimeError("文件验证失败：" + item["path"])\n    if plan["action"] == "mtu":\n        if int(Path("/sys/class/net", plan["interface"], "mtu").read_text()) != plan["after_mtu"]:\n            raise RuntimeError("MTU 未生效")\n    elif plan["action"] == "ntp":\n        if command(["timedatectl", "show", "-p", "NTP", "--value"]).stdout.strip() != "yes":\n            raise RuntimeError("NTP 未启用；启用也不等于已经同步")\n    elif plan["action"] == "mss":\n        for rule in plan["rules"]:\n            command(["iptables", "-w", "5", "-t", "mangle", "-C"] + rule)\n\n\ndef save_tx(directory, tx):\n    atomic_write(directory / "transaction.json", json.dumps(tx, indent=2).encode())\n\n\n@contextlib.contextmanager\ndef state_lock(blocking=False):\n    import fcntl\n    if STATE_ROOT.is_symlink(): raise RuntimeError("状态目录不能是符号链接")\n    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)\n    st = STATE_ROOT.stat()\n    if st.st_uid != 0 or st.st_mode & 0o077: raise RuntimeError("状态目录必须 root 所有且权限 0700")\n    fd = os.open(str(STATE_ROOT / "lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)\n    try:\n        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))\n        yield\n    finally:\n        os.close(fd)\n\n\ndef load_tx(run_id):\n    if not re.fullmatch(r"[0-9]{14}-[0-9a-f]{12}", run_id): raise RuntimeError("无效事务 ID")\n    directory = STATE_ROOT / run_id\n    if directory.is_symlink(): raise RuntimeError("事务路径不能是链接")\n    return directory, json.loads((directory / "transaction.json").read_text())\n\n\ndef rollback_tx(directory, tx, automatic=False):\n    if tx["state"] in ("rolled_back", "committed") and automatic: return\n    if tx["state"] == "rolled_back": return\n    if tx["state"] == "committed": raise RuntimeError("已提交事务不可直接撤销；请先重新规划以防覆盖之后的变更")\n    plan, errors = tx["plan"], []\n    for item in plan["files"]:\n        try:\n            p = Path(item["path"])\n            before = base64.b64decode(item["data"]) if item["data"] else None\n            actual = p.read_bytes() if p.exists() and not p.is_symlink() else None\n            if actual == before and not p.is_symlink(): continue\n            if actual != base64.b64decode(item["after"]) or p.is_symlink():\n                raise RuntimeError("文件有外部变更，拒绝覆盖：" + item["path"])\n            restore_file(item)\n        except Exception as exc:\n            errors.append(str(exc))\n    try:\n        if plan["action"] == "mtu":\n            current = int(Path("/sys/class/net", plan["interface"], "mtu").read_text())\n            if current not in (plan["before_mtu"], plan["after_mtu"]): raise RuntimeError("MTU 有外部变更，拒绝覆盖")\n            command(["ip", "link", "set", "dev", plan["interface"], "mtu", str(plan["before_mtu"])])\n        elif plan["action"] == "ntp":\n            command(["timedatectl", "set-ntp", "true" if plan["before_ntp"] == "yes" else "false"])\n        elif plan["action"] == "mss":\n            for rule in plan.get("rules", []):\n                if command(["iptables", "-w", "5", "-t", "mangle", "-C"] + rule, check=False).returncode == 0:\n                    command(["iptables", "-w", "5", "-t", "mangle", "-D"] + rule)\n    except Exception as exc:\n        errors.append(str(exc))\n    tx["state"] = "rollback_failed" if errors else "rolled_back"\n    tx["errors"] = errors\n    save_tx(directory, tx)\n    if errors: raise RuntimeError("回滚未完成：" + "; ".join(errors))\n\n\ndef apply_plan(plan, args):\n    if plan["action"] == "flush-dns":\n        command(plan["operations"][0]); print("缓存刷新命令成功；无持久配置变更")\n        return 0\n    if not Path("/run/systemd/system").is_dir() or not shutil.which("systemd-run"):\n        raise RuntimeError("此环境无法创建可靠的独立回滚计时器，拒绝应用；仍可查看修复计划")\n    for d in STATE_ROOT.iterdir():\n        f = d / "transaction.json"\n        if d.is_dir() and f.exists():\n            if json.loads(f.read_text()).get("state") in ("prepared", "pending", "rollback_failed"):\n                raise RuntimeError("存在未完成事务，请先提交或回滚：" + d.name)\n    run_id = time.strftime("%Y%m%d%H%M%S") + "-" + os.urandom(6).hex()\n    directory = STATE_ROOT / run_id\n    directory.mkdir(mode=0o700)\n    if plan["action"] == "mss":\n        plan["rules"] = [[chain, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment",\n                          "--comment", "vps-netcheck:" + run_id, "-j", "TCPMSS", "--clamp-mss-to-pmtu"]\n                         for chain in ("OUTPUT", "FORWARD")]\n    tx = {"id": run_id, "state": "prepared", "plan": plan}\n    save_tx(directory, tx)\n    # Store a standalone rollback runner so disconnecting the invoking shell cannot cancel it.\n    runner = directory / "rollback.py"\n    source = REPAIR_SOURCE if "REPAIR_SOURCE" in globals() else Path(__file__).read_text(encoding="utf-8")\n    atomic_write(runner, (source + "\\nif __name__ == \'__main__\':\\n    with state_lock(blocking=True):\\n        d,t=load_tx(sys.argv[1]); rollback_tx(d,t,automatic=True)\\n").encode())\n    unit = "vps-netcheck-" + run_id\n    try:\n        command(["systemd-run", "--quiet", "--unit", unit, "--on-active=%ds" % args.rollback_after,\n                 "--timer-property=AccuracySec=1s", sys.executable, str(runner), run_id])\n        for item in plan["files"]:\n            current = snapshot_file(item["path"])\n            if current["data"] != item["data"] or current["exists"] != item["exists"]:\n                raise RuntimeError("规划后文件状态改变，拒绝覆盖")\n            atomic_write(Path(item["path"]), base64.b64decode(item["after"]), item.get("mode", 0o644))\n            if item["exists"]: os.chown(item["path"], item["uid"], item["gid"])\n        for argv in plan["operations"]: command(argv)\n        for rule in plan.get("rules", []): command(["iptables", "-w", "5", "-t", "mangle", "-A"] + rule)\n        verify_plan(plan)\n        tx["state"] = "pending"\n        save_tx(directory, tx)\n    except Exception:\n        rollback_tx(directory, tx)\n        raise\n    print("已应用并通过本地状态验证；%d 秒后自动回滚。" % args.rollback_after)\n    print("验证 SSH/业务后提交：bash vps-netcheck-v2.sh --commit " + run_id)\n    print("立即回滚：bash vps-netcheck-v2.sh --rollback " + run_id)\n    return 0\n\n\ndef confirm_repair():\n    # Do not open a terminal with buffered r+: it requires seek support.\n    with open("/dev/tty", "r", encoding="utf-8") as reader, \\\n            open("/dev/tty", "w", encoding="utf-8", buffering=1) as writer:\n        writer.write("按以上计划应用？[y/N] "); writer.flush()\n        return reader.readline().strip().lower() == "y"\n\n\ndef repair_main(args):\n    try:\n        if args.commit or args.rollback or args.apply:\n            if not hasattr(os, "geteuid") or os.geteuid() != 0: raise RuntimeError("应用/提交/回滚需要 Linux root")\n        if args.commit or args.rollback:\n            with state_lock():\n                d, tx = load_tx(args.commit or args.rollback)\n                if args.commit:\n                    if tx["state"] != "pending": raise RuntimeError("仅能提交 pending 事务")\n                    verify_plan(tx["plan"])\n                    # Commit marker first: a timer racing with stop will see committed under the lock.\n                    tx["state"] = "committed"; save_tx(d, tx)\n                    command(["systemctl", "stop", "vps-netcheck-" + tx["id"] + ".timer"], check=False)\n                    print("事务已提交；MTU/MSS 仍仅当前运行时生效")\n                else:\n                    rollback_tx(d, tx)\n                    command(["systemctl", "stop", "vps-netcheck-" + tx["id"] + ".timer"], check=False)\n                    print("事务已回滚")\n            return 0\n        if not 30 <= args.rollback_after <= 900: raise RuntimeError("回滚时限需为 30..900 秒")\n        plan = build_plan(args)\n        print(json.dumps(plan, ensure_ascii=False, indent=2))\n        if not args.apply: print("仅显示计划；未修改系统。应用需显式加 --apply。"); return 0\n        if not args.yes:\n            if not confirm_repair(): print("已取消"); return 0\n        with state_lock():\n            # Rebuild under lock to capture the actual pre-apply state.\n            current = build_plan(args)\n            if current != plan: raise RuntimeError("确认期间系统状态改变，请重新规划")\n            return apply_plan(plan, args)\n    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:\n        print("修复未成功：" + str(exc), file=sys.stderr)\n        return 4\n'
exec(compile(_repair.REPAIR_SOURCE, '<netcheck_repair>', 'exec'), _repair.__dict__)
sys.modules['netcheck_repair'] = _repair

#!/usr/bin/env python3
"""VPS network diagnostics. Python >=3.8, standard library only."""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

VERSION = "2.0.0-rc1"
DEFAULT_URLS = ["https://www.cloudflare.com/", "https://www.google.com/",
                "https://github.com/", "https://www.microsoft.com/", "https://www.baidu.com/"]
TG_ENDPOINTS = ["149.154.175.50", "149.154.167.51", "149.154.175.100",
                "149.154.167.91", "91.108.56.130"]
ACTIVE = set()
ACTIVE_LOCK = threading.RLock()
STOP = threading.Event()


def cancel_all(signum=None, frame=None):
    STOP.set()
    with ACTIVE_LOCK:
        for p in list(ACTIVE):
            terminate(p)


def terminate(p):
    try:
        if os.name == "posix":
            os.killpg(p.pid, signal.SIGKILL)
        else:
            p.kill()
    except (ProcessLookupError, PermissionError):
        pass


def run(argv, timeout=10):
    if STOP.is_set():
        return {"rc": 130, "stdout": "", "stderr": "cancelled", "duration": 0}
    started = time.monotonic()
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, env=env, start_new_session=os.name == "posix")
    except OSError as exc:
        return {"rc": 127, "stdout": "", "stderr": str(exc), "duration": 0}
    with ACTIVE_LOCK:
        ACTIVE.add(p)
    rc = None
    try:
        try:
            out, err = p.communicate(timeout=max(.1, timeout))
        except subprocess.TimeoutExpired:
            terminate(p)
            out, err = p.communicate()
            rc = 124
        return {"rc": rc if rc is not None else p.returncode,
                "stdout": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace"),
                "duration": round(time.monotonic() - started, 3)}
    finally:
        with ACTIVE_LOCK:
            ACTIVE.discard(p)


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError("无效 IP: " + value)


def bounded_curl(argv, limit, timeout):
    """Bound body memory on old/new curl; metrics use a separate stderr channel."""
    if STOP.is_set():
        return {"rc": 130, "stdout": "", "stderr": "cancelled", "duration": 0, "body": "", "body_bytes": 0}
    started = time.monotonic()
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C", LANG="C"),
                             start_new_session=os.name == "posix")
    except OSError as exc:
        return {"rc": 127, "stdout": "", "stderr": str(exc), "duration": 0, "body": "", "body_bytes": 0}
    with ACTIVE_LOCK: ACTIVE.add(p)
    data = {"bytes": 0, "limited": False, "body": bytearray(), "err": bytearray()}
    def body_reader():
        while True:
            chunk = p.stdout.read1(16384)
            if not chunk: break
            data["bytes"] += len(chunk)
            data["body"].extend(chunk[:max(0, 8192 - len(data["body"]))])
            if data["bytes"] > limit:
                data["limited"] = True
                terminate(p)
                break
        p.stdout.close()
    def error_reader():
        while True:
            chunk = p.stderr.read1(8192)
            if not chunk: break
            data["err"].extend(chunk)
            if len(data["err"]) > 65536: del data["err"][:-65536]
        p.stderr.close()
    threads = [threading.Thread(target=body_reader), threading.Thread(target=error_reader)]
    for t in threads: t.start()
    rc = None
    try:
        try: p.wait(timeout=max(.1, timeout))
        except subprocess.TimeoutExpired:
            rc = 124; terminate(p); p.wait()
        for t in threads: t.join()
    finally:
        with ACTIVE_LOCK: ACTIVE.discard(p)
    err = data["err"].decode("utf-8", "replace").replace("\r\n", "\n")
    error, sep, metrics = err.rpartition("\nVPS_NETCHECK_METRICS\n")
    return {"rc": 63 if data["limited"] else rc if rc is not None else p.returncode,
            "stdout": metrics if sep else "", "stderr": error if sep else err,
            "duration": round(time.monotonic() - started, 3),
            "body": data["body"].decode("utf-8", "replace"), "body_bytes": data["bytes"]}


def valid_target(value):
    if not value or any(ord(c) < 33 for c in value):
        raise argparse.ArgumentTypeError("目标包含空白或控制字符")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        name = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        raise argparse.ArgumentTypeError("无效域名")
    if len(name) > 253 or re.fullmatch(r"[0-9.]+", name):
        raise argparse.ArgumentTypeError("无效目标")
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
               for x in name.split(".")):
        raise argparse.ArgumentTypeError("无效域名: " + value)
    return name


def valid_url(value):
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise argparse.ArgumentTypeError("URL 包含空白、控制字符或反斜杠")
    try:
        u = urlsplit(value)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
            raise ValueError()
        valid_target(u.hostname)
        port = u.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, argparse.ArgumentTypeError):
        raise argparse.ArgumentTypeError("仅支持不含用户名密码的有效 HTTP(S) URL: " + value)
    return value


def safe_text(text):
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(text))


def redact_url(value):
    try:
        u = urlsplit(value)
        if u.scheme in ("http", "https"):
            return urlunsplit((u.scheme, u.netloc, u.path, "REDACTED" if u.query else "", ""))
    except ValueError:
        pass
    return value


def result(probe, target, status, observation, **kw):
    return dict(probe=probe, target=target, status=status, observation=observation, **kw)


def parse_ping(text, rc):
    match = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received", text)
    if not match:
        return {"status": "UNKNOWN", "attempted": None, "received": None, "loss_pct": None,
                "rtt_mean_ms": None, "rtt_stddev_ms": None, "reason": "无可解析统计，不能认定丢包"}
    sent, received = map(int, match.groups())
    timings = re.search(r"(?:rtt|round-trip).*?=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", text)
    vals = list(map(float, timings.groups())) if timings else [None] * 4
    loss = 100 * (sent - received) / sent if sent else None
    return {"status": "PASS" if sent and received == sent else "WARN", "attempted": sent,
            "received": received, "loss_pct": loss, "rtt_min_ms": vals[0], "rtt_mean_ms": vals[1],
            "rtt_max_ms": vals[2], "rtt_stddev_ms": vals[3], "command_rc": rc}


def parse_mtr(text, target):
    try:
        raw = json.loads(text)
        hubs = raw["report"]["hubs"]
    except (ValueError, KeyError, TypeError):
        hubs = []
        for line in text.splitlines():
            m = re.match(r"\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)", line)
            if m:
                n, host, loss, sent, last, avg = m.groups()
                hubs.append({"count": int(n), "host": host, "Loss%": float(loss), "Snt": int(sent), "Avg": float(avg)})
    destination = None
    for hub in hubs:
        try:
            if ipaddress.ip_address(hub.get("host", "")) == ipaddress.ip_address(target):
                destination = hub
                break
        except ValueError:
            continue
    return {"hops": hubs, "reached": destination is not None, "destination": destination}


def classify_http(rc, code):
    if rc:
        categories = {5: "proxy_dns", 6: "dns", 7: "connect", 28: "timeout", 35: "tls",
                      47: "redirect_limit", 60: "certificate", 63: "body_limit", 124: "deadline"}
        return "FAIL", categories.get(rc, "curl_error"), "请求未完整成功，保留原始错误与部分数据"
    if code and 200 <= code < 400:
        return "PASS", None, "HTTP 请求完成"
    if code and 400 <= code < 600:
        return "WARN", "http_status", "已收到 HTTP 响应；不能单凭状态码归因为线路故障或封 IP"
    return "UNKNOWN", "no_http_status", "未取得有效 HTTP 状态"


class Checker:
    def __init__(self, args):
        self.args = args
        self.deadline = time.monotonic() + args.deadline
        self.lock = threading.Lock()
        self.rows = []
        self.cache = {}
        self.budget = int(args.max_download_mb * 1000000)
        self.downloaded = 0
        self.out = Path(args.output).expanduser() if args.output else Path(tempfile.mkdtemp(prefix="vps-netcheck-"))
        self.out.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.run_dir = self.out / (time.strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(4).hex())
        self.run_dir.mkdir(mode=0o700)

    def call(self, argv, timeout=10):
        left = self.deadline - time.monotonic()
        if left <= 0:
            return {"rc": 124, "stdout": "", "stderr": "global deadline exceeded", "duration": 0}
        return run(argv, min(timeout, left))

    def add(self, row):
        with self.lock:
            self.rows.append(row)
            print("[{status}] {probe} {target}: {observation}".format(**{
                k: safe_text(v) for k, v in row.items()}), flush=True)
        return row

    def resolve(self, host, family):
        try:
            ip = ipaddress.ip_address(host)
            return {"addresses": [str(ip)] if ip.version == family else [], "source": "literal"}
        except ValueError:
            pass
        key = (host, family, tuple(self.args.dns))
        with self.lock:
            cached = self.cache.get(key)
        if cached is not None:
            return cached
        answers, evidence = [], []
        if self.args.dns:
            if not shutil.which("dig"):
                return {"addresses": [], "source": "custom", "error": "指定 DNS 需要 dig；未回退系统 DNS"}
            for server in self.args.dns:
                r = self.call(["dig", "@" + server, host, "A" if family == 4 else "AAAA",
                               "+time=2", "+tries=1", "+noall", "+answer", "+comments", "+stats"], 4)
                for line in r["stdout"].splitlines():
                    cols = line.split()
                    if len(cols) >= 5 and cols[3] == ("A" if family == 4 else "AAAA"):
                        try:
                            ip = ipaddress.ip_address(cols[4])
                            if ip.version == family:
                                answers.append(str(ip))
                        except ValueError:
                            pass
                evidence.append(dict(server=server, **r))
                if answers:
                    break
            resolved = {"addresses": list(dict.fromkeys(answers)), "source": "custom", "queries": evidence}
        else:
            # Isolate blocking libc NSS lookup in a timeout-controlled subprocess.
            code = "import socket,json,sys; print(json.dumps(sorted(set(x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,int(sys.argv[2]),socket.SOCK_STREAM)))))"
            r = self.call([sys.executable, "-c", code, host, str(socket.AF_INET if family == 4 else socket.AF_INET6)], 6)
            try:
                answers = json.loads(r["stdout"]) if r["rc"] == 0 else []
            except ValueError:
                answers = []
            resolved = {"addresses": answers, "source": "system_nss", "evidence": r}
        with self.lock:
            self.cache[key] = resolved
        return resolved

    def http(self, url, family, capture=False, sample_bytes=None):
        u = urlsplit(url)
        dns = {"addresses": [None], "source": "proxy", "note": "实际目标解析取决于代理协议"} if self.args.proxy else self.resolve(u.hostname, family)
        if not dns["addresses"]:
            return result("http", redact_url(url), "UNKNOWN", "没有该地址族的解析结果", family=family, dns=dns)
        ip = dns["addresses"][0]
        with self.lock:
            # Reserve worst-case body allowance, not just previously observed bytes.
            allowance = min(sample_bytes or 262144, self.budget)
            self.budget -= allowance
        if allowance <= 0:
            return result("http", redact_url(url), "SKIP", "下载预算已用完", family=family)
        if not shutil.which("curl"):
            return result("http", redact_url(url), "SKIP", "缺少 curl", family=family)
        port = u.port or (443 if u.scheme == "https" else 80)
        fields = ["http_code", "time_namelookup", "time_connect", "time_appconnect", "time_starttransfer",
                  "time_total", "remote_ip", "size_download", "speed_download", "redirect_url", "content_type"]
        output = self.run_dir / ("headers-" + os.urandom(8).hex())
        addr = "[" + ip + "]" if family == 6 and ip else ip
        argv = ["curl", "-q", "--silent", "--show-error", "--globoff", "--proto", "=http,https",
                "--connect-timeout", "4", "--max-time", str(self.args.timeout),
                "--max-filesize", str(allowance), "--output", "-", "--dump-header", str(output),
                "--write-out", "%{stderr}\nVPS_NETCHECK_METRICS\n" + "\n".join("%{" + f + "}" for f in fields),
                "-" + str(family)]
        if not self.args.proxy:
            argv += ["--resolve", "%s:%s:%s" % (u.hostname, port, addr)]
        if self.args.proxy:
            argv += ["--proxy", self.args.proxy, "--noproxy", ""]
        else:
            argv += ["--noproxy", "*"]
        if self.args.interface:
            argv += ["--interface", self.args.interface]
        if self.args.source:
            argv += ["--interface", self.args.source]
        if sample_bytes:
            argv += ["--range", "0-%d" % (allowance - 1)]
        argv += ["--url", url]
        left = self.deadline - time.monotonic()
        if left <= 0:
            return result("http", redact_url(url), "SKIP", "全局时限已到", family=family)
        r = bounded_curl(argv, allowance, min(left, self.args.timeout + 1))
        raw = r["stdout"].splitlines()
        metrics = dict(zip(fields, raw))
        for key in fields:
            if key.startswith("time_") or key in ("size_download", "speed_download"):
                try:
                    val = float(metrics.get(key, ""))
                    metrics[key] = val if math.isfinite(val) and val >= 0 else None
                except ValueError:
                    metrics[key] = None
        try:
            code = int(metrics.get("http_code", 0))
        except ValueError:
            code = 0
        metrics["http_code"] = code
        body = r["body"] if capture else ""
        if output.exists():
            if not code:
                with output.open("rb") as f:
                    headers = f.read(65536).decode("iso-8859-1")
                codes = re.findall(r"^HTTP/\S+\s+(\d{3})", headers, re.M)
                if codes: code = int(codes[-1]); metrics["http_code"] = code
            output.unlink()
        metrics["body_bytes_observed"] = r["body_bytes"]
        with self.lock:
            self.downloaded += r["body_bytes"]
        status, category, observation = classify_http(r["rc"], code)
        if r["rc"] == 63 and code:
            status, observation = "WARN", "收到响应，正文达到或超过采样上限；连通性已有证据"
        row = result("http", redact_url(url), status, observation, family=family, resolved_ip=ip,
                     dns=dns, curl_exit=r["rc"], error_category=category,
                     stderr=r["stderr"], metrics=metrics, body=body,
                     family_scope="proxy_connection" if self.args.proxy else "destination",
                     proxy_mode="explicit" if self.args.proxy else "direct",
                     note="不跟随重定向；DNS 为预解析，curl DNS 时间不代表解析总耗时")
        return row

    def identity(self):
        for fam in self.args.families:
            row = self.http("https://www.cloudflare.com/cdn-cgi/trace", fam, capture=True)
            ip = None
            for line in row.get("body", "").splitlines():
                if line.startswith("ip="):
                    try:
                        candidate = ipaddress.ip_address(line[3:])
                        if candidate.version == fam:
                            ip = str(candidate)
                    except ValueError:
                        pass
            row["probe"] = "identity"
            row["status"] = "PASS" if ip else "UNKNOWN"
            row["observation"] = "观测出口 IPv%d: %s" % (fam, ip) if ip else "未确认该地址族的出口身份"
            row["public_ip"] = ip
            self.add(row)

    def dns_check(self):
        if self.args.proxy:
            self.add(result("dns", "proxy", "SKIP", "代理模式不混入本地 DNS 诊断"))
            return
        for host in ["www.cloudflare.com", "github.com", "www.google.com"]:
            for fam in self.args.families:
                r = self.resolve(host, fam)
                self.add(result("dns", host, "PASS" if r["addresses"] else "UNKNOWN",
                                "解析到 " + ", ".join(r["addresses"]) if r["addresses"] else "没有答案；见原始查询状态",
                                family=fam, evidence=r))

    def tcp(self, target, port, family, count=None):
        count = count or self.args.count
        samples, errors = [], []
        if self.args.proxy:
            return result("tcp", target, "SKIP", "代理模式不混入直连 TCP 测量", family=family)
        for _ in range(count):
            if STOP.is_set() or time.monotonic() >= self.deadline:
                break
            sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_STREAM)
            try:
                sock.settimeout(min(2, max(.1, self.deadline - time.monotonic())))
                if self.args.interface:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.args.interface.encode() + b"\0")
                if self.args.source:
                    sock.bind((self.args.source, 0))
                started = time.monotonic()
                sock.connect((target, port))
                samples.append(round((time.monotonic() - started) * 1000, 3))
            except OSError as exc:
                errors.append(str(exc))
            finally:
                sock.close()
        return result("tcp", target, "PASS" if samples and not errors else "WARN" if samples else "UNKNOWN",
                      "%s/%s 次连接成功，端口 %s" % (len(samples), len(samples) + len(errors), port),
                      family=family, port=port, attempted=len(samples) + len(errors), succeeded=len(samples),
                      failed=len(errors), median_ms=statistics.median(samples) if samples else None,
                      samples_ms=samples, errors=errors)

    def ping(self, ip, family):
        if self.args.proxy or not shutil.which("ping"):
            return result("ping", ip, "SKIP", "代理模式或缺少 ping，未进行直连 ICMP")
        argv = ["ping", "-" + str(family), "-n", "-c", str(self.args.count), "-W", "2"]
        if self.args.interface or self.args.source:
            argv += ["-I", self.args.interface or self.args.source]
        r = self.call(argv + [ip], self.args.count + 4)
        stats = parse_ping(r["stdout"], r["rc"])
        return result("ping", ip, stats.pop("status"), "ICMP 样本；无响应不能单独证明业务丢包",
                      family=family, evidence=r, **stats)

    def route(self, ip, family):
        if self.args.proxy:
            return result("route", ip, "SKIP", "代理模式不混入直连路由")
        argv = ["ip", "-" + str(family), "-j", "route", "get", ip]
        if self.args.source:
            argv += ["from", self.args.source]
        if self.args.interface:
            argv += ["oif", self.args.interface]
        r = self.call(argv)
        return result("route", ip, "PASS" if r["rc"] == 0 else "UNKNOWN", "到实际目标的内核选路", family=family, evidence=r)

    def mtr(self, ip, family):
        if self.args.proxy or not shutil.which("mtr"):
            return result("mtr", ip, "SKIP", "代理模式或缺少 mtr；没有猜测是否到达")
        argv = ["mtr", "-" + str(family), "-n", "-r", "-w", "-c", str(self.args.count),
                "-m", "24", "--tcp", "-P", str(self.args.port)]
        if self.args.source:
            argv += ["-a", self.args.source]
        if self.args.interface:
            argv += ["-I", self.args.interface]
        r = self.call(argv + [ip], self.args.count + 15)
        parsed = parse_mtr(r["stdout"], ip)
        return result("mtr", ip, "PASS" if parsed["reached"] and r["rc"] == 0 else "UNKNOWN",
                      "已看到目标响应；逐跳丢包不直接等于转发丢包" if parsed["reached"] else "未证实到达目标",
                      family=family, protocol="tcp", port=self.args.port, evidence=r, **parsed)

    def pmtu(self, ip, family):
        if self.args.proxy or not shutil.which("ping"):
            return result("pmtu", ip, "SKIP", "代理模式或缺少 ping")
        evidence, passing = [], None
        # Ascending probes establish a small-packet baseline. No automatic repair.
        for size in (1200, 1280, 1400, 1452, 1472):
            argv = ["ping", "-" + str(family), "-n", "-c", "2", "-W", "2", "-M", "do", "-s", str(size)]
            if self.args.source or self.args.interface:
                argv += ["-I", self.args.source or self.args.interface]
            r = self.call(argv + [ip], 5)
            stats = parse_ping(r["stdout"], r["rc"])
            evidence.append(dict(payload=size, result=r, stats=stats))
            if stats["received"] and r["rc"] == 0:
                passing = size + (28 if family == 4 else 48)
            elif passing is None:
                break
        return result("pmtu", ip, "PASS" if passing else "UNKNOWN",
                      "观测到可通过 IP 包长下界 %s；不是建议网卡 MTU" % passing if passing else "小包基线未建立，无法判断 PMTU",
                      family=family, passing_packet_size=passing, evidence=evidence, repair_recommendations=[])

    def quality(self, targets):
        for target in targets:
            for fam in self.args.families:
                dns = self.resolve(target, fam)
                if not dns["addresses"]:
                    self.add(result("quality", target, "UNKNOWN", "该地址族无解析结果", family=fam, dns=dns))
                    continue
                ip = dns["addresses"][0]
                self.add(self.route(ip, fam))
                self.add(self.ping(ip, fam))
                self.add(self.tcp(ip, self.args.port, fam))
                if not self.args.quick:
                    self.add(self.mtr(ip, fam))
                if self.args.full:
                    self.add(self.pmtu(ip, fam))

    def system(self):
        for name, argv in [("interfaces", ["ip", "-j", "addr"]), ("sockets", ["ss", "-s"]),
                           ("clock", ["timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTP"])]:
            r = self.call(argv, 4)
            self.add(result(name, "local", "PASS" if r["rc"] == 0 else "SKIP", "采集本机状态，成功采集不等于状态健康", evidence=r))
        count, limit = None, None
        try:
            count = int(Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text())
            limit = int(Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text())
        except (OSError, ValueError):
            pass
        self.add(result("conntrack", "local", "WARN" if limit and count / limit > .9 else "PASS" if limit else "SKIP",
                        "使用量 %s / %s" % (count, limit) if limit else "此环境无可读 conntrack 计数", count=count, limit=limit))

    def speed(self):
        size = int(self.args.speed_mb * 1000000)
        for fam in self.args.families:
            row = self.http("https://speed.cloudflare.com/__down?bytes=%d" % size, fam, sample_bytes=size)
            row["probe"] = "speed"
            m = row.get("metrics", {})
            valid = row.get("curl_exit") == 0 and m.get("http_code") in (200, 206) and (m.get("size_download") or 0) >= 65536 and "html" not in m.get("content_type", "").lower()
            row["status"] = "PASS" if valid else "UNKNOWN" if row["status"] != "SKIP" else "SKIP"
            row["mbps"] = m["speed_download"] * 8 / 1000000 if valid and m.get("speed_download") is not None else None
            row["observation"] = "单源单连接样本 %.2f Mbps；不代表线路最大带宽" % row["mbps"] if row["mbps"] is not None else "无有效完整测速样本；部分字节/耗时仍保留"
            self.add(row)

    def telegram(self):
        for fam in self.args.families:
            row = self.http("https://telegram.org/", fam)
            row["probe"] = "telegram_web"
            self.add(row)
        for ip in TG_ENDPOINTS:
            if 4 in self.args.families:
                row = self.tcp(ip, 443, 4, count=3)
                row["probe"] = "telegram_endpoint"
                row["endpoint_source"] = "legacy static bootstrap list from v1.5.0; not live DC discovery"
                row["observation"] += "；仅 TCP 入口，不证明 MTProto/媒体或全球服务状态"
                self.add(row)

    def unlock(self):
        if not self.args.unlock_script or not self.args.unlock_sha256:
            self.add(result("unlock", "external", "SKIP", "需要显式提供已审查的本地脚本及 SHA-256，不自动下载执行远程代码"))
            return
        path = Path(self.args.unlock_script).resolve()
        try:
            payload = path.read_bytes()
        except OSError as exc:
            self.add(result("unlock", "external", "UNKNOWN", str(exc)))
            return
        if hashlib.sha256(payload).hexdigest() != self.args.unlock_sha256.lower():
            self.add(result("unlock", "external", "FAIL", "脚本 SHA-256 不匹配"))
            return
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.add(result("unlock", "external", "SKIP", "请以普通用户执行第三方脚本；此入口拒绝 root"))
            return
        if self.args.dns or self.args.proxy or self.args.interface or self.args.source:
            self.add(result("unlock", "external", "SKIP", "无法保证第三方使用指定 DNS/代理/接口，拒绝静默切换"))
            return
        # Execute the exact bytes just hashed, avoiding path replacement races.
        local = self.run_dir / "verified-unlock.sh"
        local.write_bytes(payload)
        r = self.call(["bash", str(local), "-M", self.args.family, "-R", self.args.unlock_region], self.args.unlock_timeout)
        self.add(result("unlock", "external", "PASS" if r["rc"] == 0 else "UNKNOWN",
                        "外部脚本进程完成；不把它的 stdout 自动解读为解锁成功",
                        sha256=self.args.unlock_sha256.lower(), evidence=r,
                        warning="顶层摘要不能验证脚本运行时下载的其他代码；只执行已审查完整依赖链的副本"))

    def save(self):
        report = {"schema_version": "1.0", "version": VERSION, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                  "platform": platform.platform(), "proxy_mode": "explicit" if self.args.proxy else "direct",
                  "families": self.args.families, "dns": self.args.dns, "interface": self.args.interface,
                  "downloaded_bytes": self.downloaded, "body_budget_bytes": int(self.args.max_download_mb * 1000000),
                  "results": self.rows, "cancelled": STOP.is_set(), "deadline_exceeded": time.monotonic() >= self.deadline}
        target = self.run_dir / "report.json"
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        text = "\n".join("[{status}] {probe} {target}: {observation}".format(**r) for r in self.rows)
        (self.run_dir / "report.txt").write_text(text + "\n", encoding="utf-8")
        print("报告：" + str(target))
        if STOP.is_set():
            return 130
        if any(r["status"] == "FAIL" for r in self.rows):
            return 1
        if report["deadline_exceeded"] or any(r["status"] in ("UNKNOWN", "SKIP") for r in self.rows):
            return 3
        return 0


def parser():
    p = argparse.ArgumentParser(prog="vps-netcheck-v2.sh", description="VPS 网络诊断 v%s：默认只读、不自动安装；Python 3.8+" % VERSION)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="跳过 mtr/PMTU")
    mode.add_argument("--full", action="store_true", help="增加 PMTU 采样")
    only = p.add_mutually_exclusive_group()
    only.add_argument("--quality-only", metavar="TARGETS")
    only.add_argument("--telegram-only", action="store_true")
    only.add_argument("--unlock-only", action="store_true")
    p.add_argument("--quality", action="append", default=[], metavar="TARGETS")
    p.add_argument("--telegram", action="store_true")
    p.add_argument("--unlock", action="store_true")
    p.add_argument("--unlock-script")
    p.add_argument("--unlock-sha256")
    p.add_argument("--unlock-region", default="0", choices=[str(x) for x in range(12)] + ["66", "88", "99"])
    p.add_argument("--unlock-timeout", type=int, default=180)
    p.add_argument("--family", "--unlock-ip", choices=["4", "6", "0"], default="4")
    p.add_argument("--url", action="append", type=valid_url, default=[])
    p.add_argument("--file", type=Path)
    p.add_argument("--dns", action="append", default=[], metavar="IP[,IP]")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--count", "--quality-count", type=int, default=5)
    p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--deadline", type=int, default=180)
    p.add_argument("--max-download-mb", type=float, default=30)
    p.add_argument("--speed", action="store_true", help="显式启用下载测速")
    p.add_argument("--speed-mb", type=float, default=5)
    bind = p.add_mutually_exclusive_group()
    bind.add_argument("--interface")
    bind.add_argument("--source", type=valid_ip)
    p.add_argument("--proxy", help="显式代理 URL；DNS 对照与代理解析语义不同，结果会标注")
    p.add_argument("--output", help="报告根目录")
    p.add_argument("--no-install", action="store_true", help="兼容参数；新版始终不自动安装")
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--version", action="version", version=VERSION)
    p.add_argument("--fix", action="store_true", help="显示修复策略，不自动推导并执行修复")
    p.add_argument("--repair", choices=["mtu", "dns", "ipv4-prefer", "mss", "ntp", "flush-dns"])
    p.add_argument("--value", help="MTU 数值或逗号分隔 DNS 地址")
    p.add_argument("--apply", action="store_true", help="应用显式修复并启动自动回滚计时器")
    p.add_argument("--yes", action="store_true", help="跳过交互确认；不自动提交事务")
    p.add_argument("--rollback-after", type=int, default=120)
    tx = p.add_mutually_exclusive_group()
    tx.add_argument("--commit", metavar="RUN_ID")
    tx.add_argument("--rollback", metavar="RUN_ID")
    return p


def interactive_options(args):
    # A TTY is not seekable. Buffered r+ creates BufferedRandom and fails;
    # separate reader/writer streams also work when stdin carries our heredoc.
    with open("/dev/tty", "r", encoding="utf-8") as reader, \
            open("/dev/tty", "w", encoding="utf-8", buffering=1) as writer:
        writer.write("1 快速体检 / 2 完整体检 / 3 Telegram / 4 指定目标\n选择 [1]: ")
        writer.flush()
        line = reader.readline()
        if not line:
            raise OSError("终端输入已关闭，未开始检测")
        choice = line.strip() or "1"
        if choice == "1": args.quick, args.full = True, False
        elif choice == "2": args.quick, args.full = False, True
        elif choice == "3": args.telegram_only = True
        elif choice == "4":
            writer.write("目标 IP/域名（逗号分隔）: "); writer.flush()
            args.quality_only = reader.readline().strip()
            if not args.quality_only: raise ValueError("未指定目标")
        else:
            raise ValueError("无效菜单选项")


def main(argv=None):
    STOP.clear()
    p = parser()
    args = p.parse_args(argv)
    if args.interactive:
        try:
            interactive_options(args)
        except OSError as exc:
            p.error("无法访问交互终端：%s；无终端环境请指定 --quick 等 CLI 参数" % exc)
        except ValueError as exc:
            p.error(str(exc))
    try:
        args.dns = [valid_ip(x.strip()) for item in args.dns for x in item.split(",")]
        targets = [valid_target(x.strip()) for item in args.quality + ([args.quality_only] if args.quality_only else []) for x in item.split(",")]
        if args.file:
            for line in args.file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"): args.url.append(valid_url(line))
    except (argparse.ArgumentTypeError, OSError, UnicodeError) as exc:
        p.error(str(exc))
    if not 1 <= args.port <= 65535 or not 1 <= args.count <= 100 or not 1 <= args.jobs <= 8:
        p.error("port=1..65535、count=1..100、jobs=1..8")
    if not 1 <= args.timeout <= 60 or not 5 <= args.deadline <= 3600:
        p.error("timeout=1..60、deadline=5..3600")
    if not 0 < args.max_download_mb <= 1000 or not 0 < args.speed_mb <= 100 or not 1 <= args.unlock_timeout <= 900:
        p.error("下载预算或外部脚本超时超出范围")
    if args.interface and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", args.interface):
        p.error("无效接口名")
    if args.proxy:
        try:
            u = urlsplit(args.proxy)
            proxy_valid = u.scheme in ("http", "https", "socks5", "socks5h") and u.hostname and not u.username and not u.password and (u.port is None or 1 <= u.port <= 65535) and not any(ord(c) < 33 for c in args.proxy)
        except ValueError:
            proxy_valid = False
        if not proxy_valid:
            p.error("代理需有效 URL；本版不接受嵌入凭据")
        if args.dns:
            p.error("本版不组合 --proxy 与 --dns，防止混淆代理端解析")
    args.families = [4, 6] if args.family == "0" else [int(args.family)]
    if args.source and ipaddress.ip_address(args.source).version not in args.families:
        p.error("源地址与地址族不匹配")
    if args.source and len(args.families) != 1:
        p.error("绑定源地址时请显式指定单一 --family")
    if args.apply and not args.repair:
        p.error("--apply 必须指定 --repair")
    if (args.repair or args.commit or args.rollback) and (args.quality or args.quality_only or args.telegram or args.telegram_only or args.unlock or args.unlock_only or args.url or args.speed):
        p.error("修复事务与诊断选项需分次执行")
    if args.repair and (args.commit or args.rollback):
        p.error("不能同时新建和提交/回滚事务")
    if args.value and not args.repair:
        p.error("--value 仅用于 --repair")
    if args.commit or args.rollback or args.repair:
        from netcheck_repair import repair_main
        return repair_main(args)
    if args.fix:
        print("先按证据选择动作：--repair mtu|dns|ipv4-prefer|mss|ntp|flush-dns。默认仅显示计划。\n不自动关闭 IPv6，不根据一次探测修改系统。")
        return 0
    if platform.system() != "Linux":
        p.error("实际检测仅支持 Linux；本机可运行离线测试或 --help")
    os.umask(0o077)
    for s in (signal.SIGINT, signal.SIGTERM): signal.signal(s, cancel_all)
    checker = Checker(args)
    try:
        if args.quality_only:
            checker.quality(targets)
        elif args.telegram_only:
            checker.telegram()
        elif args.unlock_only:
            checker.unlock()
        else:
            checker.system()
            checker.identity()
            checker.dns_check()
            urls = list(dict.fromkeys(DEFAULT_URLS + args.url))
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = [pool.submit(checker.http, url, fam) for url in urls for fam in args.families]
                for future in concurrent.futures.as_completed(futures):
                    try: checker.add(future.result())
                    except Exception as exc: checker.add(result("http", "worker", "UNKNOWN", str(exc)))
            checker.quality(targets or ["1.1.1.1" if args.family != "6" else "2606:4700:4700::1111"])
            if args.speed: checker.speed()
            if args.telegram: checker.telegram()
            if args.unlock: checker.unlock()
    except Exception as exc:
        checker.add(result("internal", "runtime", "UNKNOWN", safe_text(exc)))
    finally:
        cancel_all() if STOP.is_set() else None
    return checker.save()


if __name__ == "__main__":
    sys.exit(main())

VPS_NETCHECK_PYTHON_EOF
