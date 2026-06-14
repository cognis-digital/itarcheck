"""Smoke tests for ITARCHECK. Standard library only, no network."""

import json
import subprocess
import sys
from pathlib import Path

import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from itarcheck import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Severity,
    USML_CATEGORIES,
    scan_text,
    scan_path,
    summarize,
)
from itarcheck.cli import main  # noqa: E402
from itarcheck.core import exceeds_threshold  # noqa: E402

DEMO = REPO_ROOT / "demos" / "01-basic" / "fcu_datasheet.txt"


class TestMetadata(unittest.TestCase):
    def test_tool_identity(self):
        self.assertEqual(TOOL_NAME, "itarcheck")
        self.assertTrue(TOOL_VERSION)
        self.assertEqual(len(USML_CATEGORIES), 21)


class TestEngine(unittest.TestCase):
    def test_clean_text_no_findings(self):
        findings = scan_text("def add(a, b):\n    return a + b\n")
        self.assertEqual(findings, [])

    def test_detects_guidance_high(self):
        findings = scan_text("The terminal guidance computer drives the IMU.")
        self.assertTrue(findings)
        self.assertTrue(any(f.severity is Severity.HIGH for f in findings))
        self.assertTrue(any(f.usml_category == "XII" for f in findings))

    def test_detects_crypto_ear(self):
        findings = scan_text("We use an AES-256 encryption module.")
        self.assertTrue(any(f.regime == "EAR" for f in findings))
        self.assertTrue(any(f.ear_reason for f in findings))

    def test_embargo_destination_flagged(self):
        findings = scan_text("Do not export to China for this build.")
        self.assertTrue(any(f.rule_id == "ADV-COUNTRY" for f in findings))

    def test_line_and_column_tracking(self):
        text = "clean line\nthe warhead is heavy\n"
        findings = scan_text(text)
        self.assertTrue(findings)
        self.assertEqual(findings[0].line, 2)
        self.assertGreaterEqual(findings[0].column, 1)


class TestScanPath(unittest.TestCase):
    def test_scan_demo_file(self):
        result = scan_path(DEMO)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(result.findings)
        self.assertGreater(result.counts["high"], 0)
        self.assertIn("finding", summarize(result))
        self.assertTrue(exceeds_threshold(result, Severity.HIGH))

    def test_scan_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_path(REPO_ROOT / "does-not-exist-xyz")

    def test_skips_binary(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "blob.bin"
            p.write_bytes(b"\x00\x01guided missile\x00")
            result = scan_path(p)
            self.assertEqual(result.files_skipped, 1)
            self.assertEqual(result.findings, [])


class TestCLI(unittest.TestCase):
    def test_scan_returns_one_on_high(self):
        rc = main(["scan", str(DEMO)])
        self.assertEqual(rc, 1)

    def test_scan_clean_returns_zero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "clean.py"
            p.write_text("print('hello world')\n")
            self.assertEqual(main(["scan", str(p)]), 0)

    def test_categories_zero(self):
        self.assertEqual(main(["categories"]), 0)

    def test_json_output_is_valid(self):
        proc = subprocess.run(
            [sys.executable, "-m", "itarcheck", "scan",
             str(DEMO), "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertIn("findings", payload)
        self.assertTrue(payload["gate_failed"])
        self.assertEqual(payload["fail_on"], "high")

    def test_version_flag(self):
        proc = subprocess.run(
            [sys.executable, "-m", "itarcheck", "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(TOOL_VERSION, proc.stdout)


class TestHardening(unittest.TestCase):
    """Tests added to cover new error / edge-case paths."""

    # --- CLI: missing file returns exit code 2 --------------------------------

    def test_cli_missing_file_returns_exit_2(self):
        rc = main(["scan", "/absolutely/no/such/path/xyz123"])
        self.assertEqual(rc, 2)

    def test_cli_missing_file_subprocess_exit_2(self):
        proc = subprocess.run(
            [sys.executable, "-m", "itarcheck", "scan", "/no/such/path/abc"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr.lower())

    # --- CLI: bad --ext flag (missing leading dot) returns exit code 2 --------

    def test_cli_bad_ext_no_dot_returns_exit_2(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "clean.txt"
            p.write_text("nothing here\n")
            rc = main(["scan", str(p), "--ext", "vhd"])
            self.assertEqual(rc, 2)

    def test_cli_ext_with_dot_is_accepted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "clean.vhd"
            p.write_text("nothing here\n")
            rc = main(["scan", str(d), "--ext", ".vhd"])
            self.assertEqual(rc, 0)

    # --- core: scan_text on empty input returns empty list --------------------

    def test_scan_text_empty_string(self):
        self.assertEqual(scan_text(""), [])

    def test_scan_text_whitespace_only(self):
        self.assertEqual(scan_text("   \n  \t  \n"), [])

    # --- core: scan_path rejects invalid max_bytes ----------------------------

    def test_scan_path_zero_max_bytes_raises(self):
        with self.assertRaises(ValueError):
            scan_path(REPO_ROOT / "demos", max_bytes=0)

    def test_scan_path_negative_max_bytes_raises(self):
        with self.assertRaises(ValueError):
            scan_path(REPO_ROOT / "demos", max_bytes=-1)

    def test_scan_path_invalid_extension_type_raises(self):
        with self.assertRaises(ValueError):
            scan_path(REPO_ROOT / "demos", extensions=[""])

    # --- mcp_server: module compiles with correct imports ---------------------

    def test_mcp_server_imports_cleanly(self):
        """mcp_server must not import non-existent names from core."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mcp_server",
            REPO_ROOT / "itarcheck" / "mcp_server.py",
        )
        mod = importlib.util.module_from_spec(spec)
        # Should not raise ImportError for missing 'scan' / 'to_json'
        try:
            spec.loader.exec_module(mod)
        except ImportError as exc:
            self.fail(f"mcp_server import raised ImportError: {exc}")

    # --- webhook: empty stdin / invalid URL handled cleanly ------------------

    def test_webhook_empty_stdin_returns_2(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "integrations" / "webhook.py"),
             "--url", "http://localhost:9999"],
            input="",
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("empty", proc.stderr.lower())

    def test_webhook_bad_json_returns_2(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "integrations" / "webhook.py"),
             "--url", "http://localhost:9999"],
            input="not valid json at all!!!",
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("json", proc.stderr.lower())

    def test_webhook_bad_url_scheme_returns_2(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "integrations" / "webhook.py"),
             "--url", "ftp://example.com/findings"],
            input='{"findings": []}',
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr.lower())

    def test_webhook_malformed_header_returns_2(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "integrations" / "webhook.py"),
             "--url", "http://localhost:9999",
             "--header", "BadHeaderNoColon"],
            input='{"findings": []}',
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr.lower())


if __name__ == "__main__":
    unittest.main()
