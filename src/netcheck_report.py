"""Human-readable reports shared by the terminal and report.txt."""
import json
import math
import re


STATUS = {"PASS": "通过", "WARN": "注意", "FAIL": "失败", "UNKNOWN": "未确定", "SKIP": "已跳过"}
PROBES = {"interfaces": "网卡", "sockets": "连接统计", "clock": "系统时间", "conntrack": "连接跟踪表",
          "identity": "公网身份", "dns": "DNS", "http": "HTTP/HTTPS", "route": "内核路由",
          "ping": "ICMP", "tcp": "TCP", "mtr": "路由追踪", "pmtu": "路径 MTU",
          "quality": "目标质量", "speed": "下载测速", "telegram_web": "Telegram 官网",
          "telegram_endpoint": "Telegram 入口", "unlock": "流媒体", "internal": "运行错误"}
GROUPS = [("本机状态", {"interfaces", "sockets", "clock", "conntrack"}),
          ("公网身份与 DNS", {"identity", "dns"}), ("网站连通与耗时", {"http"}),
          ("目标网络质量与路由", {"quality", "route", "ping", "tcp", "mtr", "pmtu"}),
          ("下载测速", {"speed"}), ("Telegram", {"telegram_web", "telegram_endpoint"}),
          ("流媒体", {"unlock"})]


def clean(value):
    text = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", str(value))
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)


def number(value, unit="", digits=2):
    if isinstance(value, bool): return "--"
    try:
        val = float(value)
        if not math.isfinite(val) or val < 0: return "--"
    except (TypeError, ValueError):
        return "--"
    return ("%.*f" % (digits, val)).rstrip("0").rstrip(".") + unit if digits else str(int(val)) + unit


def milliseconds(value):
    try: return number(float(value) * 1000, " ms")
    except (TypeError, ValueError): return "--"


def phase(metrics, end, start):
    try:
        a, b = float(metrics[end]), float(metrics[start])
        if a <= 0 or a < b: return "--"
        return milliseconds(a - b)
    except (KeyError, TypeError, ValueError):
        return "--"


def heading(row):
    state = row.get("status", "UNKNOWN")
    fam = " IPv%s" % row["family"] if row.get("family") else ""
    if row.get("family_scope") == "proxy_connection": fam += "（代理连接）"
    return "[%s] %s%s  %s" % (STATUS.get(state, clean(state)),
                              PROBES.get(row.get("probe"), clean(row.get("probe", ""))), fam,
                              clean(row.get("target", "")))


def progress_line(row):
    return heading(row) + "：" + clean(row.get("observation", ""))


def raw_lines(value, prefix="    "):
    return [prefix + clean(line) for line in str(value).splitlines() if clean(line).strip()]


def dns_lines(dns):
    lines = []
    if dns.get("addresses"):
        addresses = [clean(x) for x in dns["addresses"] if x is not None]
        if addresses: lines.append("    解析地址：" + ", ".join(addresses))
    source = dns.get("source")
    labels = {"literal": "IP 字面量", "system_nss": "系统解析", "custom": "指定 DNS", "proxy": "代理解析"}
    if source: lines.append("    解析方式：" + labels.get(source, clean(source)))
    if dns.get("error"): lines.append("    解析错误：" + clean(dns["error"]))
    for q in dns.get("queries", []):
        stdout = q.get("stdout", "")
        status = re.search(r"status:\s*(\w+)", stdout)
        timing = re.search(r"Query time:\s*(\d+)\s*msec", stdout)
        lines.append("    DNS %s：%s，查询 %s，退出码 %s" % (
            clean(q.get("server", "--")), status.group(1) if status else "无响应状态",
            timing.group(1) + " ms" if timing else "--", q.get("rc", "--")))
        if q.get("stderr"): lines += raw_lines(q["stderr"], "      ")
    evidence = dns.get("evidence", {})
    if evidence.get("rc") and evidence.get("stderr"):
        lines += raw_lines(evidence["stderr"], "    解析错误：")
    return lines


def detail(row):
    lines = [heading(row), "    " + clean(row.get("observation", ""))]
    probe = row.get("probe")
    metrics = row.get("metrics", {})
    evidence = row.get("evidence", {})
    if row.get("public_ip"): lines.append("    公网 IP：" + clean(row["public_ip"]))
    if metrics:
        code = metrics.get("http_code") or "--"
        lines.append("    HTTP %s | 实际对端 %s | curl 退出码 %s" % (
            code, clean(metrics.get("remote_ip") or "--"), row.get("curl_exit", "--")))
        lines.append("    TCP %s | TLS %s | TTFB %s | 总耗时 %s" % (
            phase(metrics, "time_connect", "time_namelookup"),
            "不适用" if str(row.get("target", "")).startswith("http://") else phase(metrics, "time_appconnect", "time_connect"),
            milliseconds(metrics.get("time_starttransfer")), milliseconds(metrics.get("time_total"))))
        lines.append("    正文字节 %s | 平均下载 %s B/s" % (
            number(metrics.get("body_bytes_observed", metrics.get("size_download")), digits=0),
            number(metrics.get("speed_download"))))
        if metrics.get("redirect_url"):
            lines.append("    重定向（未跟随）：" + clean(metrics["redirect_url"]))
    if row.get("error_category"): lines.append("    错误类别：" + clean(row["error_category"]))
    if row.get("stderr"): lines += raw_lines(row["stderr"], "    错误：")
    if probe == "dns": lines += dns_lines(evidence)
    elif row.get("dns"): lines += dns_lines(row["dns"])
    if probe == "ping" and "attempted" in row:
        lines.append("    发送 %s / 收到 %s | 丢包 %s" % (
            number(row.get("attempted"), digits=0), number(row.get("received"), digits=0), number(row.get("loss_pct"), "%")))
        lines.append("    RTT 最小 %s | 平均 %s | 最大 %s | 标准差 %s" % tuple(
            number(row.get(k), " ms") for k in ("rtt_min_ms", "rtt_mean_ms", "rtt_max_ms", "rtt_stddev_ms")))
    if probe in ("tcp", "telegram_endpoint") and "attempted" in row:
        lines.append("    端口 %s | 连接成功 %s/%s | 失败 %s | 中位耗时 %s" % (
            row.get("port", "--"), row.get("succeeded", 0), row.get("attempted", 0),
            row.get("failed", 0), number(row.get("median_ms"), " ms")))
        if row.get("samples_ms"):
            lines.append("    成功样本（ms）：" + ", ".join(number(x) for x in row["samples_ms"]))
        for error in dict.fromkeys(row.get("errors", [])): lines.append("    连接错误：" + clean(error))
    if probe == "speed": lines.append("    有效测速：" + number(row.get("mbps"), " Mbps"))
    if probe == "conntrack":
        lines.append("    当前 %s / 上限 %s" % (number(row.get("count"), digits=0), number(row.get("limit"), digits=0)))
    if probe in ("interfaces", "route") and isinstance(evidence, dict):
        try:
            entries = json.loads(evidence.get("stdout", ""))
            if not isinstance(entries, list): raise ValueError()
            for entry in entries:
                if probe == "interfaces":
                    addresses = ["%s/%s" % (x.get("local", ""), x.get("prefixlen", "")) for x in entry.get("addr_info", [])]
                    lines.append("    %s | 状态 %s | MTU %s | 地址 %s" % (clean(entry.get("ifname", "--")),
                        clean(entry.get("operstate", "--")), clean(entry.get("mtu", "--")), clean(", ".join(addresses)) or "--"))
                else:
                    lines.append("    接口 %s | 源地址 %s | 网关 %s" % (clean(entry.get("dev", "--")),
                        clean(entry.get("prefsrc", entry.get("src", "--"))), clean(entry.get("gateway", "直连/未返回"))))
        except (ValueError, TypeError, AttributeError):
            lines += raw_lines(evidence.get("stdout", ""))
    elif probe in ("sockets", "clock", "mtr", "unlock") and isinstance(evidence, dict):
        if probe == "mtr":
            lines.append("    协议 %s / 端口 %s | 已证实到达目标：%s" % (
                clean(row.get("protocol", "--")), row.get("port", "--"), "是" if row.get("reached") else "否"))
        lines += raw_lines(evidence.get("stdout", ""))
    if isinstance(evidence, dict) and evidence.get("stderr"):
        lines += raw_lines(evidence["stderr"], "    工具提示：")
    if probe == "pmtu" and isinstance(evidence, list):
        for sample in evidence:
            stats = sample.get("stats", {})
            lines.append("    payload %s：收到 %s/%s，退出码 %s" % (sample.get("payload", "--"),
                number(stats.get("received"), digits=0), number(stats.get("attempted"), digits=0), sample.get("result", {}).get("rc", "--")))
    if row.get("warning"): lines.append("    提醒：" + clean(row["warning"]))
    return "\n".join(lines)


def render_report(report):
    rows = report.get("results", [])
    counts = {state: sum(r.get("status") == state for r in rows) for state in STATUS}
    lines = ["", "=" * 64, "VPS 网络体检报告  v" + clean(report.get("version", "")),
             "时间：" + clean(report.get("time", "")),
             "通过 {PASS} | 注意 {WARN} | 失败 {FAIL} | 未确定 {UNKNOWN} | 已跳过 {SKIP}".format(**counts)]
    if report.get("cancelled"): lines.append("本轮已中断；以下仅包含已取得的结果。")
    if report.get("deadline_exceeded"): lines.append("已达到总时限，部分检测可能未完成。")
    lines.append("正文接收量：%s 字节" % number(report.get("downloaded_bytes"), digits=0))
    lines += ["", "优先关注"]
    issues = sorted([r for r in rows if r.get("status") != "PASS"],
                    key=lambda r: {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "SKIP": 3}.get(r.get("status"), 4))
    if issues:
        lines.extend("  " + progress_line(row) for row in issues)
    else:
        lines.append("  本轮没有记录异常；结果仅代表此次探测的目标和时间。" if rows else "  没有取得检测结果。")
    covered = set()
    for title, probes in GROUPS:
        group = [r for r in rows if r.get("probe") in probes]
        if group:
            lines += ["", "─" * 32, title, "─" * 32]
            lines.extend(detail(row) + "\n" for row in group)
            covered |= probes
    other = [r for r in rows if r.get("probe") not in covered]
    if other: lines += ["", "其他结果"] + [detail(row) for row in other]
    if any(r.get("metrics") for r in rows):
        lines.append("耗时说明：TCP/TLS 为阶段差值，TTFB/总耗时从请求开始累计；DNS 已预解析，缺测用 -- 表示。")
    lines.append("判断说明：HTTP 拒绝、ICMP 无响应或中间跳丢包，不能单独证明整机网络故障。")
    lines.append("=" * 64)
    return "\n".join(lines) + "\n"
