import argparse
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import netcheck as n
import netcheck_repair as r


def args_for(output, *extra):
    a = n.parser().parse_args(["--output", str(output)] + list(extra))
    a.families = [4, 6] if a.family == "0" else [int(a.family)]
    return a


class Validation(unittest.TestCase):
    def test_bad_ipv4(self):
        for text in ("999.1.1.1", "256.1.1.1", "1.2.3", "01.2.3.4"):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError): n.valid_ip(text)

    def test_bad_ipv6(self):
        for text in ("abc:def", "foo:bar", "::1:xyz"):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError): n.valid_target(text)

    def test_valid_addresses(self):
        self.assertEqual(n.valid_ip("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(n.valid_target("example.com"), "example.com")

    def test_bad_urls(self):
        for text in ("file:///etc/passwd", "--config=x", "https://a:99999", "https://u:p@a", "https://a/\nX"):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError): n.valid_url(text)

    def test_ipv6_url_port(self):
        self.assertEqual(n.valid_url("https://[2001:db8::1]:8443/a#b"), "https://[2001:db8::1]:8443/a#b")

    def test_parser_conflicts(self):
        for argv in (["--quick", "--full"], ["--quality-only", "1.1.1.1", "--telegram-only"],
                     ["--unlock-region", "';echo bad"], ["--apply"], ["--dns", "999.1.1.1"],
                     ["--source", "::1"], ["--proxy", "http://127.0.0.1:80", "--dns", "1.1.1.1"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): n.main(argv)

    def test_redaction(self):
        self.assertEqual(n.redact_url("https://example.com/x?token=secret#abc"), "https://example.com/x?REDACTED")

    def test_control_text(self):
        self.assertNotIn("\x1b", n.safe_text("bad\x1b[2J"))


class Parsers(unittest.TestCase):
    def test_ping_success(self):
        x = n.parse_ping("5 packets transmitted, 4 received, 20% packet loss\nrtt min/avg/max/mdev = 1.1/2.2/3.3/0.4 ms", 0)
        self.assertEqual(x["loss_pct"], 20)
        self.assertEqual(x["rtt_stddev_ms"], .4)

    def test_ping_permission_is_unknown(self):
        x = n.parse_ping("ping: socket: Operation not permitted", 2)
        self.assertEqual(x["status"], "UNKNOWN")
        self.assertIsNone(x["loss_pct"])

    def test_ping_total_loss(self):
        x = n.parse_ping("5 packets transmitted, 0 received, 100% packet loss", 1)
        self.assertEqual(x["loss_pct"], 100)
        self.assertIsNone(x["rtt_mean_ms"])

    def test_mtr_intermediate_not_destination(self):
        x = n.parse_mtr(" 1.|-- 192.0.2.1 0.0% 20 1.0 1.1 1.0 1.4 0.1", "203.0.113.1")
        self.assertFalse(x["reached"])

    def test_mtr_destination(self):
        x = n.parse_mtr(" 2.|-- 203.0.113.1 5.0% 20 1.0 1.1 1.0 1.4 0.1", "203.0.113.1")
        self.assertTrue(x["reached"])
        self.assertEqual(x["destination"]["Loss%"], 5)

    def test_mtr_header_only(self):
        x = n.parse_mtr("traceroute to 203.0.113.1 (203.0.113.1), 30 hops\n 1 * * *", "203.0.113.1")
        self.assertFalse(x["reached"])

    def test_mtr_ipv6_normalizes(self):
        x = n.parse_mtr(json.dumps({"report": {"hubs": [{"host": "2001:0db8::1", "Loss%": 0}]}}), "2001:db8::1")
        self.assertTrue(x["reached"])

    def test_http_403_not_transport_fail(self):
        self.assertEqual(n.classify_http(0, 403)[0], "WARN")

    def test_http_500_not_pass(self):
        self.assertEqual(n.classify_http(0, 500)[0], "WARN")

    def test_certificate_distinct_from_timeout(self):
        self.assertEqual(n.classify_http(60, 0)[1], "certificate")
        self.assertEqual(n.classify_http(28, 0)[1], "timeout")


class Execution(unittest.TestCase):
    def setUp(self): n.STOP.clear()

    def test_timeout_preserves_output(self):
        x = n.run([sys.executable, "-u", "-c", "import time; print('partial'); time.sleep(20)"], .3)
        self.assertEqual(x["rc"], 124)
        self.assertIn("partial", x["stdout"])
        self.assertFalse(n.ACTIVE)

    def test_missing_command(self):
        self.assertEqual(n.run(["nonexistent-vps-netcheck-test-command"])["rc"], 127)

    def test_bounded_body(self):
        code = "import sys; sys.stdout.buffer.write(b'x'*1000000); sys.stdout.flush()"
        x = n.bounded_curl([sys.executable, "-c", code], 1024, 5)
        self.assertEqual(x["rc"], 63)
        self.assertLessEqual(len(x["body"]), 8192)
        self.assertFalse(n.ACTIVE)

    def test_metrics_separate_from_body(self):
        code = "import sys; print('body'); sys.stderr.write('diagnostic\\nVPS_NETCHECK_METRICS\\n200\\n0.01')"
        x = n.bounded_curl([sys.executable, "-c", code], 1024, 5)
        self.assertEqual(x["stdout"], "200\n0.01")
        self.assertEqual(x["stderr"], "diagnostic")
        self.assertIn("body", x["body"])

    def test_cancelled_does_not_start(self):
        n.STOP.set()
        with patch.object(n.subprocess, "Popen") as proc:
            self.assertEqual(n.run(["curl"])["rc"], 130)
            proc.assert_not_called()


class Probes(unittest.TestCase):
    def setUp(self):
        n.STOP.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.c = n.Checker(args_for(self.tmp.name))

    def test_custom_dns_no_system_fallback(self):
        self.c.args.dns = ["192.0.2.53", "198.51.100.53"]
        with patch.object(n.shutil, "which", return_value="dig"), patch.object(self.c, "call", return_value={"rc": 9, "stdout": "", "stderr": "timeout"}) as call:
            x = self.c.resolve("example.com", 4)
        self.assertEqual(x["addresses"], [])
        self.assertEqual(call.call_count, 2)
        self.assertTrue(all(c.args[0][0] == "dig" for c in call.call_args_list))

    def test_dns_cname_filtered_and_second_resolver(self):
        self.c.args.dns = ["192.0.2.53", "198.51.100.53"]
        replies = [{"rc": 9, "stdout": "", "stderr": "timeout"}, {"rc": 0, "stdout": "example.com. 30 IN CNAME cdn.example.com.\ncdn.example.com. 30 IN A 203.0.113.1", "stderr": ""}]
        with patch.object(n.shutil, "which", return_value="dig"), patch.object(self.c, "call", side_effect=replies):
            self.assertEqual(self.c.resolve("example.com", 4)["addresses"], ["203.0.113.1"])

    def test_missing_dig_explicit_error(self):
        self.c.args.dns = ["1.1.1.1"]
        with patch.object(n.shutil, "which", return_value=None):
            self.assertIn("未回退", self.c.resolve("example.com", 4)["error"])

    def test_custom_port_and_tls_error_preserved(self):
        fake = {"rc": 60, "stdout": "000\n.01\n.02\n0\n0\n.1\n203.0.113.1\n0\n0\n\n", "stderr": "certificate verify failed", "body": "", "body_bytes": 0}
        with patch.object(self.c, "resolve", return_value={"addresses": ["203.0.113.1"]}), patch.object(n.shutil, "which", return_value="curl"), patch.object(n, "bounded_curl", return_value=fake) as call:
            x = self.c.http("https://example.com:8443", 4)
        self.assertIn("example.com:8443:203.0.113.1", call.call_args.args[0])
        self.assertEqual(x["error_category"], "certificate")
        self.assertEqual(x["metrics"]["time_connect"], .02)

    def test_http_403_ipv6(self):
        fake = {"rc": 0, "stdout": "403\n.01\n.02\n.03\n.04\n.05\n2001:db8::1\n10\n200\n\ntext/html", "stderr": "", "body": "", "body_bytes": 10}
        with patch.object(self.c, "resolve", return_value={"addresses": ["2001:db8::1"]}), patch.object(n.shutil, "which", return_value="curl"), patch.object(n, "bounded_curl", return_value=fake):
            x = self.c.http("https://example.com", 6)
        self.assertEqual(x["status"], "WARN")
        self.assertNotIn("repair", x)

    def test_budget_skips_without_execution(self):
        self.c.budget = 0
        with patch.object(self.c, "resolve", return_value={"addresses": ["203.0.113.1"]}), patch.object(n, "bounded_curl") as call:
            self.assertEqual(self.c.http("https://example.com", 4)["status"], "SKIP")
            call.assert_not_called()

    def test_no_mtr_no_guessed_reachability(self):
        with patch.object(n.shutil, "which", return_value=None):
            x = self.c.mtr("203.0.113.1", 4)
        self.assertEqual(x["status"], "SKIP")
        self.assertNotIn("reached", x)

    def test_tcp_failed_samples_counted(self):
        sock = Mock()
        sock.connect.side_effect = [None, OSError("timeout"), OSError("timeout"), OSError("timeout"), OSError("timeout")]
        with patch.object(n.socket, "socket", return_value=sock):
            x = self.c.tcp("203.0.113.1", 443, 4, count=5)
        self.assertEqual((x["attempted"], x["succeeded"], x["failed"]), (5, 1, 4))
        self.assertEqual(x["status"], "WARN")

    def test_mtu_no_repair_inferred(self):
        with patch.object(n.shutil, "which", return_value="ping"), patch.object(self.c, "call", return_value={"rc": 1, "stdout": "2 packets transmitted, 0 received", "stderr": ""}):
            x = self.c.pmtu("203.0.113.1", 4)
        self.assertEqual(x["status"], "UNKNOWN")
        self.assertEqual(x["repair_recommendations"], [])

    def test_speed_500_rejected(self):
        row = n.result("http", "x", "WARN", "HTTP 500", curl_exit=0, metrics={"http_code": 500, "size_download": 100000, "speed_download": 1000000})
        with patch.object(self.c, "http", return_value=row), contextlib.redirect_stdout(io.StringIO()): self.c.speed()
        self.assertIsNone(self.c.rows[0]["mbps"])
        self.assertEqual(self.c.rows[0]["status"], "UNKNOWN")

    def test_report_failure_exit_and_null(self):
        self.c.rows = [n.result("http", "x", "FAIL", "cert", value=None)]
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.c.save(), 1)
        self.assertIsNone(json.loads((self.c.run_dir / "report.json").read_text())["results"][0]["value"])

    def test_report_unknown_exit(self):
        self.c.rows = [n.result("http", "x", "UNKNOWN", "no evidence")]
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.c.save(), 3)

    def test_unlock_missing_artifact_never_runs(self):
        with patch.object(self.c, "call") as call, contextlib.redirect_stdout(io.StringIO()):
            self.c.unlock(); call.assert_not_called()
        self.assertEqual(self.c.rows[-1]["status"], "SKIP")


class Repairs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "config"
        self.path.write_bytes(b"original")

    def test_snapshot_is_content(self):
        snap = r.snapshot_file(str(self.path))
        self.path.write_bytes(b"modified")
        self.assertEqual(base64.b64decode(snap["data"]), b"original")

    def test_reject_symlink(self):
        with patch.object(r.Path, "is_symlink", return_value=True), self.assertRaises(RuntimeError): r.snapshot_file(str(self.path))

    def test_atomic_restoration(self):
        snap = r.snapshot_file(str(self.path))
        self.path.write_bytes(b"modified")
        with patch.object(r.os, "chown", create=True): r.restore_file(snap)
        self.assertEqual(self.path.read_bytes(), b"original")

    def test_rollback_refuses_external_edits(self):
        snap = r.snapshot_file(str(self.path))
        snap["after"] = base64.b64encode(b"intended").decode()
        self.path.write_bytes(b"someone else")
        tx = {"state": "pending", "plan": {"action": "dns", "files": [snap]}}
        with self.assertRaises(RuntimeError): r.rollback_tx(Path(self.tmp.name), tx)
        self.assertEqual(self.path.read_bytes(), b"someone else")
        self.assertEqual(tx["state"], "rollback_failed")

    def test_timer_does_nothing_after_commit(self):
        tx = {"state": "committed"}
        with patch.object(r, "restore_file") as restore:
            r.rollback_tx(Path(self.tmp.name), tx, automatic=True); restore.assert_not_called()

    def test_plan_never_writes(self):
        a = args_for(self.tmp.name, "--repair", "ipv4-prefer")
        snap = r.snapshot_file(str(self.path))
        with patch.object(r, "snapshot_file", return_value=snap): plan = r.build_plan(a)
        self.assertEqual(self.path.read_bytes(), b"original")
        self.assertIn(b"precedence ::1/128 50", base64.b64decode(plan["files"][0]["after"]))

    def test_existing_gai_policy_refused(self):
        snap = r.snapshot_file(str(self.path)); snap["data"] = base64.b64encode(b"precedence ::/0 100\n").decode()
        with patch.object(r, "snapshot_file", return_value=snap), self.assertRaises(RuntimeError): r.build_plan(args_for(self.tmp.name, "--repair", "ipv4-prefer"))

    def test_mss_rollback_only_owned_rules(self):
        rule = ["OUTPUT", "-m", "comment", "--comment", "vps-netcheck:unique"]
        tx = {"state": "pending", "plan": {"action": "mss", "files": [], "rules": [rule]}}
        with patch.object(r, "command", return_value=Mock(returncode=0)) as cmd:
            r.rollback_tx(Path(self.tmp.name), tx)
        self.assertTrue(all("vps-netcheck:unique" in c.args[0] for c in cmd.call_args_list))
        self.assertEqual(tx["state"], "rolled_back")

    def test_timer_failure_does_not_modify_config(self):
        snap = r.snapshot_file(str(self.path)); snap["after"] = base64.b64encode(b"new").decode()
        plan = {"action": "dns", "files": [snap], "operations": []}
        original_is_dir = Path.is_dir
        def is_dir(p): return True if str(p).replace("\\", "/") == "/run/systemd/system" else original_is_dir(p)
        with patch.object(r, "STATE_ROOT", Path(self.tmp.name)), patch.object(Path, "is_dir", is_dir), patch.object(r.shutil, "which", return_value="systemd-run"), patch.object(r, "command", side_effect=RuntimeError("timer failed")):
            with self.assertRaises(RuntimeError): r.apply_plan(plan, args_for(self.tmp.name))
        self.assertEqual(self.path.read_bytes(), b"original")

    def test_apply_snapshot_and_pending_transaction(self):
        snap = r.snapshot_file(str(self.path)); snap["after"] = base64.b64encode(b"new").decode()
        plan = {"action": "dns", "files": [snap], "operations": []}
        original_is_dir = Path.is_dir
        def is_dir(p): return True if str(p).replace("\\", "/") == "/run/systemd/system" else original_is_dir(p)
        with patch.object(r, "STATE_ROOT", Path(self.tmp.name)), patch.object(Path, "is_dir", is_dir), patch.object(r.shutil, "which", return_value="systemd-run"), patch.object(r.os, "chown", create=True), patch.object(r, "command", return_value=Mock(returncode=0)) as cmd, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.apply_plan(plan, args_for(self.tmp.name)), 0)
        self.assertEqual(self.path.read_bytes(), b"new")
        txfile = list(Path(self.tmp.name).glob("*/transaction.json"))[0]
        tx = json.loads(txfile.read_text())
        self.assertEqual(tx["state"], "pending")
        self.assertEqual(cmd.call_args_list[0].args[0][0], "systemd-run")
        compile((txfile.parent / "rollback.py").read_text(encoding="utf-8"), "runner", "exec")
        with patch.object(r.os, "chown", create=True): r.rollback_tx(txfile.parent, tx)
        self.assertEqual(self.path.read_bytes(), b"original")


if __name__ == "__main__": unittest.main(verbosity=2)
