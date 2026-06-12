import json
import sys
import tempfile
import unittest
from pathlib import Path

# 50% LLM, 50% me

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.exporter import export_json, export_reports


class ExporterTests(unittest.TestCase):
    def test_export_json_writes_expected_payload(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "single.json"
            payload = {"b": 2, "a": 1}

            export_json(payload, output)

            self.assertTrue(output.exists())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), payload)

    def test_export_reports_writes_named_json_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            reports = {
                "anyrun": {"ok": True},
                "virustotal": {"ok": True},
                "radare2": {"ok": True},
                "yara": [{"rule": "dummy"}],
            }

            exported = export_reports(output_dir, reports)

            self.assertEqual(set(exported.keys()), set(reports.keys()))
            for report_name in reports:
                output = output_dir / f"{report_name}.json"
                self.assertTrue(output.exists())
                self.assertEqual(json.loads(output.read_text(encoding="utf-8")), reports[report_name])


if __name__ == "__main__":
    unittest.main()