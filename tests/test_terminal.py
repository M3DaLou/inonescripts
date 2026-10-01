"""Terminal regression: real non-seekable pipes, plus a real PTY on POSIX."""
import contextlib
import io
import os
from pathlib import Path
import select
import shutil
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import netcheck as n
import netcheck_repair as r


class PipeTerminal(unittest.TestCase):
    @contextlib.contextmanager
    def terminal(self, answer):
        read_fd, feed_fd = os.pipe()
        capture_fd, write_fd = os.pipe()
        os.write(feed_fd, answer)
        os.close(feed_fd)
        opened_modes = []
        real_open = open
        def open_terminal(path, mode, **kwargs):
            self.assertEqual(path, "/dev/tty")
            opened_modes.append(mode)
            # Use actual non-seekable file descriptors, not StringIO mocks.
            fd = read_fd if mode.startswith("r") else write_fd
            return real_open(fd, mode, closefd=False, **kwargs)
        try:
            with patch("builtins.open", side_effect=open_terminal):
                yield opened_modes
        finally:
            os.close(read_fd); os.close(write_fd)
            self.prompt = os.read(capture_fd, 8192).decode("utf-8")
            os.close(capture_fd)

    def test_buffered_update_mode_requires_seekable_stream(self):
        class TerminalRaw(io.RawIOBase):
            def readable(self): return True
            def writable(self): return True
            def seekable(self): return False
        with TerminalRaw() as raw, self.assertRaises(io.UnsupportedOperation):
            io.BufferedRandom(raw)

    def test_default_menu_on_nonseekable_stream(self):
        args = n.parser().parse_args([])
        with self.terminal(b"\n") as modes:
            n.interactive_options(args)
        self.assertTrue(args.quick)
        self.assertFalse(args.full)
        self.assertEqual(modes, ["r", "w"])
        self.assertIn("选择 [1]", self.prompt)

    def test_full_menu_overrides_quick(self):
        args = n.parser().parse_args(["--quick"])
        with self.terminal(b"2\n"):
            n.interactive_options(args)
        self.assertTrue(args.full)
        self.assertFalse(args.quick)

    def test_target_menu_second_prompt(self):
        args = n.parser().parse_args([])
        with self.terminal(b"4\nexample.com,1.1.1.1\n30\n8443\n4\n"):
            n.interactive_options(args)
        self.assertEqual(args.quality_only, "example.com,1.1.1.1")
        self.assertEqual(args.count, 30)
        self.assertEqual(args.port, 8443)
        self.assertIn("目标 IP", self.prompt)

    def test_menu_ipv6_target_defaults_to_ipv6(self):
        args = n.parser().parse_args([])
        with self.terminal(b"4\n2001:db8::1\n\n\n\n"):
            n.interactive_options(args)
        self.assertEqual(args.family, "6")

    def test_menu_can_quit_without_scanning(self):
        with self.terminal(b"q\n"):
            self.assertFalse(n.interactive_options(n.parser().parse_args([])))
        self.assertIn("未开始检测", self.prompt)

    def test_menu_reprompts_invalid_input(self):
        args = n.parser().parse_args([])
        with self.terminal(b"invalid\n1\n"):
            self.assertTrue(n.interactive_options(args))
        self.assertTrue(args.quick)
        self.assertIn("重新输入", self.prompt)

    def test_menu_website_accepts_bare_domain(self):
        args = n.parser().parse_args([])
        with self.terminal(b"6\nexample.com\n"):
            n.interactive_options(args)
        self.assertEqual(args.url, ["https://example.com"])

    def test_menu_double_stack(self):
        args = n.parser().parse_args([])
        with self.terminal(b"8\n"):
            n.interactive_options(args)
        self.assertEqual(args.family, "0")
        self.assertTrue(args.full)

    def test_eof_does_not_start_default_scan(self):
        with self.terminal(b""), self.assertRaises(OSError):
            n.interactive_options(n.parser().parse_args([]))

    def test_missing_tty_preserves_actual_error(self):
        output = io.StringIO()
        with patch("builtins.open", side_effect=OSError("NO_CONTROLLING_TTY")), contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
            n.main(["--interactive"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("NO_CONTROLLING_TTY", output.getvalue())
        self.assertIn("vps-netcheck-v2.sh", output.getvalue())

    def test_repair_confirmation_accepts_yes(self):
        with self.terminal(b"y\n") as modes:
            self.assertTrue(r.confirm_repair())
        self.assertEqual(modes, ["r", "w"])

    def test_repair_confirmation_eof_declines(self):
        with self.terminal(b""):
            self.assertFalse(r.confirm_repair())


@unittest.skipUnless(os.name == "posix", "real controlling PTY requires POSIX")
class PosixTerminal(unittest.TestCase):
    def test_menu_with_controlling_tty_and_non_tty_stdin(self):
        def child():
            try:
                with open("/dev/tty", "r+"):
                    return 11  # The original buggy mode should fail on this TTY.
            except io.UnsupportedOperation:
                pass
            args = n.parser().parse_args([])
            n.interactive_options(args)
            return 0 if args.full else 9
        self.pty_run(child)

    @unittest.skipUnless(shutil.which("bash"), "Bash is unavailable")
    def test_standalone_heredoc_launcher_menu(self):
        def child():
            script = str(Path(__file__).resolve().parents[1] / "vps-netcheck-v2.sh")
            # --fix displays advice only; no actual network or repair operation.
            os.execv(shutil.which("bash"), ["bash", script, "--interactive", "--fix"])
        self.pty_run(child)

    def pty_run(self, child):
        import pty
        pid, master = pty.fork()
        if pid == 0:
            try:
                # Like python3 - <<EOF: stdin is not the controlling terminal.
                null = os.open(os.devnull, os.O_RDONLY)
                os.dup2(null, 0); os.close(null)
                os._exit(child())
            except BaseException:
                os._exit(10)
        try:
            output = b""
            deadline = time.monotonic() + 5
            while b"[1]:" not in output and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], .1)
                if ready:
                    try: output += os.read(master, 8192)
                    except OSError: break
            self.assertIn(b"[1]:", output)
            os.write(master, b"2\n")
            while time.monotonic() < deadline:
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    self.assertEqual(status, 0)
                    pid = None
                    break
                time.sleep(.02)
            self.assertIsNone(pid, "PTY child did not complete")
        finally:
            os.close(master)
            if pid:
                import signal
                os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)


if __name__ == "__main__": unittest.main(verbosity=2)
