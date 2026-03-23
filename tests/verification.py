from __future__ import annotations

import io
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from perimeter.cli import main
from perimeter.storage import IPReportStorage


class VerificationTests(unittest.TestCase):
    def test_analyze_store_report_saves_target_scoped_reports(self) -> None:
        xml_text = textwrap.dedent(
            """\
            <nmaprun>
              <host>
                <status state="up" />
                <address addr="192.168.1.10" />
                <hostnames><hostname name="web-1" /></hostnames>
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open" />
                    <service name="http" version="Apache" />
                  </port>
                </ports>
              </host>
              <host>
                <status state="up" />
                <address addr="192.168.1.20" />
                <hostnames><hostname name="files-1" /></hostnames>
                <ports>
                  <port protocol="tcp" portid="445">
                    <state state="open" />
                    <service name="microsoft-ds" version="Windows" />
                  </port>
                </ports>
              </host>
            </nmaprun>
            """
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            xml_path = tmp_path / "scan.xml"
            reports_dir = tmp_path / "reports"
            xml_path.write_text(xml_text, encoding="utf-8")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "analyze",
                        str(xml_path),
                        "--store-report",
                        "--reports-dir",
                        str(reports_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)

            storage = IPReportStorage(reports_dir)
            report_10 = storage.get_target_reports("192.168.1.10")[0][1]
            report_20 = storage.get_target_reports("192.168.1.20")[0][1]

            self.assertEqual(report_10["summary"]["hosts_analyzed"], 1)
            self.assertEqual(report_10["summary"]["open_ports_analyzed"], 1)
            self.assertEqual(len(report_10["findings"]), 1)
            self.assertEqual(report_10["findings"][0]["host"], "192.168.1.10")
            self.assertEqual(report_10["host"]["hostnames"], ["web-1"])

            self.assertEqual(report_20["summary"]["hosts_analyzed"], 1)
            self.assertEqual(report_20["summary"]["open_ports_analyzed"], 1)
            self.assertEqual(len(report_20["findings"]), 1)
            self.assertEqual(report_20["findings"][0]["host"], "192.168.1.20")
            self.assertEqual(report_20["findings"][0]["service"], "microsoft-ds")

    def test_storage_round_trips_ipv6_targets(self) -> None:
        report = {"summary": {"hosts_analyzed": 1}, "findings": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = IPReportStorage(tmpdir)
            saved_path = storage.save_report("fe80::1", report)

            self.assertTrue(saved_path.exists())
            self.assertNotIn(":", saved_path.parent.name)
            self.assertEqual(storage.list_targets(), ["fe80::1"])
            reports = storage.get_target_reports("fe80::1")
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0][1]["target"], "fe80::1")

    def test_save_report_uses_unique_filenames_within_same_second(self) -> None:
        report = {"summary": {"hosts_analyzed": 1}, "findings": []}
        dt1 = datetime(2026, 3, 23, 10, 15, 30, 123456)
        dt2 = datetime(2026, 3, 23, 10, 15, 30, 654321)

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = IPReportStorage(tmpdir)
            with patch("perimeter.storage.datetime") as mocked_datetime:
                mocked_datetime.now.side_effect = [dt1, dt2]
                path1 = storage.save_report("192.168.1.10", report)
                path2 = storage.save_report("192.168.1.10", report)

            self.assertNotEqual(path1, path2)
            self.assertTrue(path1.exists())
            self.assertTrue(path2.exists())
            self.assertEqual(storage.get_report_count("192.168.1.10"), 2)


if __name__ == "__main__":
    unittest.main()
