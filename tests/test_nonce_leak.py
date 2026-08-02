import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class NonceLeakRegression(unittest.TestCase):
    """Regression test for the --nonce memory leak in `nvattest attest`."""

    @staticmethod
    def _nvattest_path() -> Path:
        env_bin = os.environ.get("NVATTEST_BIN")
        if env_bin:
            return Path(env_bin)
        repo_root = Path(__file__).resolve().parents[1]
        candidates = [
            repo_root / "build" / "nvattest",
            repo_root / "build" / "nv-attestation-cli" / "nvattest",
            repo_root / "build" / "src" / "nvattest",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    def test_attest_with_nonce_does_not_leak(self):
        if not shutil.which("valgrind"):
            self.skipTest("valgrind is required to detect memory leaks")

        nvattest = self._nvattest_path()
        if not nvattest.exists():
            self.skipTest(f"nvattest binary not found: {nvattest}")

        # A 32-byte nonce (64 hex chars) exercises nvat_nonce_from_hex and
        # the subsequent nvat_attest_device call that previously leaked.
        nonce = "00" * 32

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "valgrind.log"
            cmd = [
                "valgrind",
                "--leak-check=full",
                "--errors-for-leak-kinds=definite",
                "--log-file=" + str(log_file),
                str(nvattest),
                "attest",
                "--nonce",
                nonce,
            ]
            subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log = log_file.read_text()

            match = re.search(r"definitely lost:\s+([\d,]+)\s+bytes", log)
            if not match:
                self.skipTest("could not parse valgrind leak summary")

            leaked = int(match.group(1).replace(",", ""))
            self.assertEqual(
                leaked,
                0,
                f"nvattest leaked {leaked} bytes when --nonce is supplied:\n{log}",
            )


if __name__ == "__main__":
    unittest.main()
