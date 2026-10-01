import contextlib
import io
import json
import os
from pathlib import Path
import sys
import shutil
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import netcheck as n
import netcheck_report as report


def fixture(rows):
    return {"version": n.VERSION, "time": "2026-10-01", "results": rows, "downloaded_bytes": 200}


class Reports(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "standalone diagnostic requires Linux/Bash")
    def test_standalone_prints_full_report_without_network_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(__file__).resolve().parents[1] / "vps-netcheck-v2.sh"
            # Literal target + proxy mode skips all direct quality probes.
            run = subprocess.run(["bash", str(script), "--quick", "--quality-only", "127.0.0.1",
                "--proxy", "http://127.0.0.1:9", "--output", tmp], capture_output=True, text=True,
                encoding="utf-8", timeout=10)
            self.assertEqual(run.returncode, 3, run.stderr)
            self.assertIn("VPS 网络体检报告", run.stdout)
            self.assertIn("目标网络质量与路由", run.stdout)
            saved = list(Path(tmp).glob("*/report.txt"))
            self.assertEqual(len(saved), 1)
            self.assertIn(saved[0].read_text(encoding="utf-8"), run.stdout)

    def test_http_details_visible_without_opening_json(self):
        row = n.result("http", "https://example.com", "WARN", "HTTP 拒绝", family=6, curl_exit=0,
            metrics={"http_code": 403, "remote_ip": "2001:db8::1", "time_namelookup": .01,
                     "time_connect": .03, "time_appconnect": .08, "time_starttransfer": .1,
                     "time_total": .2, "size_download": 200, "speed_download": 1000})
        text = report.render_report(fixture([row]))
        for value in ("网站连通与耗时", "HTTP 403", "2001:db8::1", "TCP 20 ms", "TLS 50 ms", "TTFB 100 ms", "总耗时 200 ms"):
            self.assertIn(value, text)

    def test_ping_and_tcp_numbers_visible(self):
        rows = [n.result("ping", "1.1.1.1", "WARN", "ICMP", attempted=20, received=19, loss_pct=5,
                         rtt_min_ms=10, rtt_mean_ms=20, rtt_max_ms=40, rtt_stddev_ms=3),
                n.result("tcp", "1.1.1.1", "WARN", "TCP", port=443, attempted=5, succeeded=1,
                         failed=4, median_ms=25, samples_ms=[25], errors=["timed out"])]
        text = report.render_report(fixture(rows))
        for value in ("丢包 5%", "平均 20 ms", "标准差 3 ms", "连接成功 1/5", "失败 4", "25 ms", "timed out"):
            self.assertIn(value, text)

    def test_mtr_hops_and_reachability_visible(self):
        row = n.result("mtr", "203.0.113.1", "UNKNOWN", "未达目标", protocol="tcp", port=8443,
                       reached=False, evidence={"stdout": "1.|-- 192.0.2.1 10.0% 20 1 2 3\n2.|-- ??? 100.0%", "rc": 0})
        text = report.render_report(fixture([row]))
        self.assertIn("已证实到达目标：否", text)
        self.assertIn("1.|-- 192.0.2.1", text)
        self.assertIn("端口 8443", text)

    def test_dns_server_rcode_and_answer_visible(self):
        row = n.result("dns", "example.com", "PASS", "解析成功", evidence={"source": "custom", "addresses": ["203.0.113.1"],
            "queries": [{"server": "1.1.1.1", "rc": 0, "stdout": ";; status: NOERROR\n;; Query time: 23 msec"}]})
        text = report.render_report(fixture([row]))
        self.assertIn("203.0.113.1", text)
        self.assertIn("DNS 1.1.1.1：NOERROR，查询 23 ms", text)

    def test_local_interface_and_route_visible(self):
        rows = [n.result("interfaces", "local", "PASS", "网卡", evidence={"stdout": json.dumps([
            {"ifname": "eth0", "mtu": 1400, "operstate": "UP", "addr_info": [{"local": "192.0.2.10", "prefixlen": 24}]}])}),
            n.result("route", "1.1.1.1", "PASS", "路由", evidence={"stdout": json.dumps([
                {"dev": "eth0", "prefsrc": "192.0.2.10", "gateway": "192.0.2.1"}])})]
        text = report.render_report(fixture(rows))
        for value in ("MTU 1400", "192.0.2.10/24", "源地址 192.0.2.10", "网关 192.0.2.1"):
            self.assertIn(value, text)

    def test_summary_prioritizes_failures(self):
        rows = [n.result("dns", "skip", "SKIP", "缺工具"), n.result("http", "failed", "FAIL", "证书错误"),
                n.result("ping", "warn", "WARN", "有丢包")]
        text = report.render_report(fixture(rows))
        summary = text.split("优先关注", 1)[1].split("─", 1)[0]
        self.assertLess(summary.index("failed"), summary.index("warn"))
        self.assertLess(summary.index("warn"), summary.index("skip"))
        self.assertIn("失败 1", text)
        self.assertIn("已跳过 1", text)

    def test_no_ansi_or_terminal_controls_in_file_report(self):
        row = n.result("http", "\x1b[2Jexample.com", "FAIL", "bad\x07", stderr="\x1b[31mcertificate\x1b[0m")
        text = report.render_report(fixture([row]))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertIn("certificate", text)

    def test_missing_measurements_are_not_zero(self):
        row = n.result("ping", "target", "UNKNOWN", "权限不足", attempted=None, received=None, loss_pct=None)
        text = report.render_report(fixture([row]))
        self.assertIn("丢包 --", text)
        self.assertNotIn("丢包 0%", text)
        self.assertEqual(report.number(0, " ms"), "0 ms")
        self.assertEqual(report.number(1000), "1000")

    def test_cancelled_report_is_marked_partial(self):
        data = fixture([]); data["cancelled"] = True; data["deadline_exceeded"] = True
        text = report.render_report(data)
        self.assertIn("已中断", text)
        self.assertIn("已达到总时限", text)

    def test_save_prints_the_same_detailed_text_it_saves(self):
        n.STOP.clear()
        with tempfile.TemporaryDirectory() as tmp:
            args = n.parser().parse_args(["--output", tmp]); args.families = [4]
            checker = n.Checker(args)
            checker.rows = [n.result("tcp", "203.0.113.1", "PASS", "连接成功", port=443,
                attempted=5, succeeded=5, failed=0, median_ms=42, samples_ms=[42] * 5)]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout): rc = checker.save()
            saved = (checker.run_dir / "report.txt").read_text(encoding="utf-8")
            self.assertIn(saved, stdout.getvalue())
            self.assertIn("中位耗时 42 ms", stdout.getvalue())
            self.assertIn("文本报告：", stdout.getvalue())
            self.assertIn("JSON 报告：", stdout.getvalue())
            self.assertEqual(rc, 0)


if __name__ == "__main__": unittest.main(verbosity=2)
