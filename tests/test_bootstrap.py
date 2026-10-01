"""Bootstrap tests replace all network/package operations with shell functions."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")


@unittest.skipUnless(BASH and Path(BASH).exists(), "Bash is unavailable")
class Bootstrap(unittest.TestCase):
    def shell(self, code):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "case.sh"
            fixture.write_bytes(("#!/usr/bin/env bash\nexport PATH=/usr/bin:/bin:$PATH\nsource \"$1\"\n" + code).encode())
            return subprocess.run([BASH, fixture.as_posix(), (ROOT / "v2.sh").as_posix()],
                                  capture_output=True, encoding="utf-8", errors="replace", timeout=15)

    def test_download_failure_never_executes(self):
        r = self.shell("v2_dependencies() { :; }\ncurl() { return 22; }\nv2_main --quick\n")
        self.assertEqual(r.returncode, 2, r.stderr)

    def test_hash_mismatch_never_executes(self):
        r = self.shell("""
v2_dependencies() { :; }
curl() {
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == -o ]]; then printf 'echo SHOULD_NOT_EXECUTE\n' > "$2"; return; fi
    shift
  done
}
v2_main --quick
""")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertNotIn("SHOULD_NOT_EXECUTE", r.stdout)

    def test_forwards_arguments_and_exit_code(self):
        r = self.shell("""
v2_dependencies() { :; }
curl() {
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == -o ]]; then
      printf '#!/usr/bin/env bash\nprintf "ARG=%%s\\n" "$@"\nexit 3\n' > "$2"
      V2_SHA256=$(sha256sum "$2"); V2_SHA256=${V2_SHA256%% *}
      return
    fi
    shift
  done
}
v2_main --url 'https://example.com/?a=1&b=2'
""")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("ARG=--url", r.stdout)
        self.assertIn("ARG=https://example.com/?a=1&b=2", r.stdout)

    def test_failed_install_never_downloads(self):
        r = self.shell("v2_dependencies() { return 2; }\ncurl() { echo SHOULD_NOT_DOWNLOAD; }\nv2_main\n")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("SHOULD_NOT_DOWNLOAD", r.stdout)

    def test_dependencies_present_skip_apt(self):
        r = self.shell("""
command() { return 0; }
dpkg-query() { printf 'install ok installed'; }
python3() { return 0; }
apt-get() { echo SHOULD_NOT_INSTALL; return 1; }
v2_dependencies
""")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("SHOULD_NOT_INSTALL", r.stdout)

    def test_missing_packages_are_deduplicated(self):
        r = self.shell("""
command() { case "${2:-}" in ip|ss|ping) return 1;; *) return 0;; esac; }
dpkg-query() { printf 'install ok installed'; }
python3() { return 0; }
sudo() { "$@"; }
env() { shift; "$@"; }
apt-get() { printf 'APT'; printf ' <%s>' "$@"; printf '\n'; }
v2_dependencies
""")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("APT <install> <-y> <iproute2> <iputils-ping>", r.stdout)
        self.assertNotIn("<iproute2> <iproute2>", r.stdout)


if __name__ == "__main__": unittest.main(verbosity=2)
