"""Explicit reversible repairs. All persistent actions are guarded by a systemd timer."""
import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

STATE_ROOT = Path("/var/lib/vps-netcheck")


def command(argv, check=True):
    r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       encoding="utf-8", errors="replace", timeout=20, env=dict(os.environ, LC_ALL="C"))
    if check and r.returncode:
        raise RuntimeError("%s: %s" % (argv[0], r.stderr.strip()))
    return r


def atomic_write(path, data, mode=0o600):
    temp = path.with_name(path.name + ".new-" + os.urandom(4).hex())
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists(): temp.unlink()


def snapshot_file(path):
    p = Path(path)
    if p.is_symlink():
        raise RuntimeError("拒绝直接修改符号链接：%s；请通过系统网络管理器配置" % path)
    if not p.exists():
        return {"path": path, "exists": False, "data": None}
    st = p.stat()
    if not p.is_file(): raise RuntimeError("目标不是普通文件")
    return {"path": path, "exists": True, "data": base64.b64encode(p.read_bytes()).decode(),
            "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid}


def restore_file(item):
    p = Path(item["path"])
    if p.is_symlink(): raise RuntimeError("回滚时文件变成符号链接，拒绝覆盖：" + str(p))
    if item["exists"]:
        atomic_write(p, base64.b64decode(item["data"]), item["mode"])
        os.chown(p, item["uid"], item["gid"])
    elif p.exists():
        p.unlink()


def choose_iface(explicit):
    if explicit:
        if not Path("/sys/class/net", explicit).exists(): raise RuntimeError("网卡不存在")
        return explicit
    r = command(["ip", "-j", "route", "get", "1.1.1.1"])
    rows = json.loads(r.stdout)
    if not rows or not rows[0].get("dev"): raise RuntimeError("无法确定接口，请指定 --interface")
    return rows[0]["dev"]


def build_plan(args):
    action = args.repair
    plan = {"action": action, "files": [], "operations": [], "scope": "", "rollback_seconds": args.rollback_after}
    if action == "mtu":
        if not args.value or not re.fullmatch(r"[0-9]{3,5}", args.value):
            raise RuntimeError("MTU 必须显式指定 --value")
        mtu = int(args.value)
        if not 1280 <= mtu <= 9000: raise RuntimeError("本版 MTU 安全范围为 1280..9000")
        iface = choose_iface(args.interface)
        old = int(Path("/sys/class/net", iface, "mtu").read_text())
        plan.update(interface=iface, before_mtu=old, after_mtu=mtu,
                    scope="仅当前接口运行时 MTU；不写开机服务，不覆盖网络管理器配置")
        plan["operations"] = [["ip", "link", "set", "dev", iface, "mtu", str(mtu)]]
    elif action == "dns":
        if not args.value: raise RuntimeError("DNS 必须显式指定 --value IP[,IP]")
        ips = [str(ipaddress.ip_address(x.strip())) for x in args.value.split(",")]
        if not 1 <= len(ips) <= 3: raise RuntimeError("DNS 数量需为 1..3")
        snap = snapshot_file("/etc/resolv.conf")
        old = base64.b64decode(snap["data"]).decode("utf-8", "replace") if snap["data"] else ""
        if re.search(r"generated|managed|resolvconf|NetworkManager|systemd", old, re.I):
            raise RuntimeError("resolv.conf 标注为自动管理，本版不覆盖；请通过对应网络管理器配置")
        # A plain resolv.conf can still be managed. Reject active managers as well.
        for unit in ("NetworkManager", "systemd-resolved", "systemd-networkd"):
            if command(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0:
                raise RuntimeError("检测到活动网络管理器 %s，本版不直接改 DNS" % unit)
        retained = [line for line in old.splitlines() if not re.match(r"\s*nameserver\s", line)]
        new = "\n".join(retained + ["nameserver " + x for x in ips]) + "\n"
        plan["files"] = [dict(snap, after=base64.b64encode(new.encode()).decode())]
        plan.update(dns=ips, scope="静态 /etc/resolv.conf；保留 search/options 等其他配置")
    elif action == "ipv4-prefer":
        snap = snapshot_file("/etc/gai.conf")
        old = base64.b64decode(snap["data"]).decode("utf-8") if snap["data"] else ""
        if re.search(r"^\s*(precedence|label)\s", old, re.M):
            raise RuntimeError("已有自定义 gai 策略，拒绝覆盖；请手工合并")
        addition = "\n# vps-netcheck managed policy\nprecedence ::1/128 50\nprecedence ::/0 40\nprecedence 2002::/16 30\nprecedence ::/96 20\nprecedence ::ffff:0:0/96 100\n"
        plan["files"] = [dict(snap, after=base64.b64encode((old + addition).encode()).decode())]
        plan["scope"] = "glibc getaddrinfo 地址排序；不保证其他 DNS 实现及已有进程缓存立即变化"
    elif action == "mss":
        if not shutil.which("iptables"): raise RuntimeError("缺少 iptables；不会自动安装")
        plan["scope"] = "IPv4 OUTPUT/FORWARD 的运行时规则；每条使用事务专属 comment，不持久化"
    elif action in ("ntp", "flush-dns"):
        plan["scope"] = "启用已有 NTP 服务" if action == "ntp" else "刷新 systemd-resolved 缓存（无可恢复前态）"
        if action == "ntp":
            old = command(["timedatectl", "show", "-p", "NTP", "--value"]).stdout.strip()
            if old not in ("yes", "no"): raise RuntimeError("无法读取 NTP 原状态")
            plan["before_ntp"] = old
            plan["operations"] = [["timedatectl", "set-ntp", "true"]]
        else:
            if not shutil.which("resolvectl"): raise RuntimeError("未发现 resolvectl，不推断有无其他缓存")
            plan["operations"] = [["resolvectl", "flush-caches"]]
    return plan


def verify_plan(plan):
    for item in plan["files"]:
        p = Path(item["path"])
        if p.is_symlink() or not p.exists() or p.read_bytes() != base64.b64decode(item["after"]):
            raise RuntimeError("文件验证失败：" + item["path"])
    if plan["action"] == "mtu":
        if int(Path("/sys/class/net", plan["interface"], "mtu").read_text()) != plan["after_mtu"]:
            raise RuntimeError("MTU 未生效")
    elif plan["action"] == "ntp":
        if command(["timedatectl", "show", "-p", "NTP", "--value"]).stdout.strip() != "yes":
            raise RuntimeError("NTP 未启用；启用也不等于已经同步")
    elif plan["action"] == "mss":
        for rule in plan["rules"]:
            command(["iptables", "-w", "5", "-t", "mangle", "-C"] + rule)


def save_tx(directory, tx):
    atomic_write(directory / "transaction.json", json.dumps(tx, indent=2).encode())


@contextlib.contextmanager
def state_lock(blocking=False):
    import fcntl
    if STATE_ROOT.is_symlink(): raise RuntimeError("状态目录不能是符号链接")
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = STATE_ROOT.stat()
    if st.st_uid != 0 or st.st_mode & 0o077: raise RuntimeError("状态目录必须 root 所有且权限 0700")
    fd = os.open(str(STATE_ROOT / "lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def load_tx(run_id):
    if not re.fullmatch(r"[0-9]{14}-[0-9a-f]{12}", run_id): raise RuntimeError("无效事务 ID")
    directory = STATE_ROOT / run_id
    if directory.is_symlink(): raise RuntimeError("事务路径不能是链接")
    return directory, json.loads((directory / "transaction.json").read_text())


def rollback_tx(directory, tx, automatic=False):
    if tx["state"] in ("rolled_back", "committed") and automatic: return
    if tx["state"] == "rolled_back": return
    if tx["state"] == "committed": raise RuntimeError("已提交事务不可直接撤销；请先重新规划以防覆盖之后的变更")
    plan, errors = tx["plan"], []
    for item in plan["files"]:
        try:
            p = Path(item["path"])
            before = base64.b64decode(item["data"]) if item["data"] else None
            actual = p.read_bytes() if p.exists() and not p.is_symlink() else None
            if actual == before and not p.is_symlink(): continue
            if actual != base64.b64decode(item["after"]) or p.is_symlink():
                raise RuntimeError("文件有外部变更，拒绝覆盖：" + item["path"])
            restore_file(item)
        except Exception as exc:
            errors.append(str(exc))
    try:
        if plan["action"] == "mtu":
            current = int(Path("/sys/class/net", plan["interface"], "mtu").read_text())
            if current not in (plan["before_mtu"], plan["after_mtu"]): raise RuntimeError("MTU 有外部变更，拒绝覆盖")
            command(["ip", "link", "set", "dev", plan["interface"], "mtu", str(plan["before_mtu"])])
        elif plan["action"] == "ntp":
            command(["timedatectl", "set-ntp", "true" if plan["before_ntp"] == "yes" else "false"])
        elif plan["action"] == "mss":
            for rule in plan.get("rules", []):
                if command(["iptables", "-w", "5", "-t", "mangle", "-C"] + rule, check=False).returncode == 0:
                    command(["iptables", "-w", "5", "-t", "mangle", "-D"] + rule)
    except Exception as exc:
        errors.append(str(exc))
    tx["state"] = "rollback_failed" if errors else "rolled_back"
    tx["errors"] = errors
    save_tx(directory, tx)
    if errors: raise RuntimeError("回滚未完成：" + "; ".join(errors))


def apply_plan(plan, args):
    if plan["action"] == "flush-dns":
        command(plan["operations"][0]); print("缓存刷新命令成功；无持久配置变更")
        return 0
    if not Path("/run/systemd/system").is_dir() or not shutil.which("systemd-run"):
        raise RuntimeError("此环境无法创建可靠的独立回滚计时器，拒绝应用；仍可查看修复计划")
    for d in STATE_ROOT.iterdir():
        f = d / "transaction.json"
        if d.is_dir() and f.exists():
            if json.loads(f.read_text()).get("state") in ("prepared", "pending", "rollback_failed"):
                raise RuntimeError("存在未完成事务，请先提交或回滚：" + d.name)
    run_id = time.strftime("%Y%m%d%H%M%S") + "-" + os.urandom(6).hex()
    directory = STATE_ROOT / run_id
    directory.mkdir(mode=0o700)
    if plan["action"] == "mss":
        plan["rules"] = [[chain, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment",
                          "--comment", "vps-netcheck:" + run_id, "-j", "TCPMSS", "--clamp-mss-to-pmtu"]
                         for chain in ("OUTPUT", "FORWARD")]
    tx = {"id": run_id, "state": "prepared", "plan": plan}
    save_tx(directory, tx)
    # Store a standalone rollback runner so disconnecting the invoking shell cannot cancel it.
    runner = directory / "rollback.py"
    source = REPAIR_SOURCE if "REPAIR_SOURCE" in globals() else Path(__file__).read_text(encoding="utf-8")
    atomic_write(runner, (source + "\nif __name__ == '__main__':\n    with state_lock(blocking=True):\n        d,t=load_tx(sys.argv[1]); rollback_tx(d,t,automatic=True)\n").encode())
    unit = "vps-netcheck-" + run_id
    try:
        command(["systemd-run", "--quiet", "--unit", unit, "--on-active=%ds" % args.rollback_after,
                 "--timer-property=AccuracySec=1s", sys.executable, str(runner), run_id])
        for item in plan["files"]:
            current = snapshot_file(item["path"])
            if current["data"] != item["data"] or current["exists"] != item["exists"]:
                raise RuntimeError("规划后文件状态改变，拒绝覆盖")
            atomic_write(Path(item["path"]), base64.b64decode(item["after"]), item.get("mode", 0o644))
            if item["exists"]: os.chown(item["path"], item["uid"], item["gid"])
        for argv in plan["operations"]: command(argv)
        for rule in plan.get("rules", []): command(["iptables", "-w", "5", "-t", "mangle", "-A"] + rule)
        verify_plan(plan)
        tx["state"] = "pending"
        save_tx(directory, tx)
    except Exception:
        rollback_tx(directory, tx)
        raise
    print("已应用并通过本地状态验证；%d 秒后自动回滚。" % args.rollback_after)
    print("验证 SSH/业务后提交：bash vps-netcheck-v2.sh --commit " + run_id)
    print("立即回滚：bash vps-netcheck-v2.sh --rollback " + run_id)
    return 0


def confirm_repair():
    # Do not open a terminal with buffered r+: it requires seek support.
    with open("/dev/tty", "r", encoding="utf-8") as reader, \
            open("/dev/tty", "w", encoding="utf-8", buffering=1) as writer:
        writer.write("按以上计划应用？[y/N] "); writer.flush()
        return reader.readline().strip().lower() == "y"


def repair_main(args):
    try:
        if args.commit or args.rollback or args.apply:
            if not hasattr(os, "geteuid") or os.geteuid() != 0: raise RuntimeError("应用/提交/回滚需要 Linux root")
        if args.commit or args.rollback:
            with state_lock():
                d, tx = load_tx(args.commit or args.rollback)
                if args.commit:
                    if tx["state"] != "pending": raise RuntimeError("仅能提交 pending 事务")
                    verify_plan(tx["plan"])
                    # Commit marker first: a timer racing with stop will see committed under the lock.
                    tx["state"] = "committed"; save_tx(d, tx)
                    command(["systemctl", "stop", "vps-netcheck-" + tx["id"] + ".timer"], check=False)
                    print("事务已提交；MTU/MSS 仍仅当前运行时生效")
                else:
                    rollback_tx(d, tx)
                    command(["systemctl", "stop", "vps-netcheck-" + tx["id"] + ".timer"], check=False)
                    print("事务已回滚")
            return 0
        if not 30 <= args.rollback_after <= 900: raise RuntimeError("回滚时限需为 30..900 秒")
        plan = build_plan(args)
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        if not args.apply: print("仅显示计划；未修改系统。应用需显式加 --apply。"); return 0
        if not args.yes:
            if not confirm_repair(): print("已取消"); return 0
        with state_lock():
            # Rebuild under lock to capture the actual pre-apply state.
            current = build_plan(args)
            if current != plan: raise RuntimeError("确认期间系统状态改变，请重新规划")
            return apply_plan(plan, args)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("修复未成功：" + str(exc), file=sys.stderr)
        return 4
