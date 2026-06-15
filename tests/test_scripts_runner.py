import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# 10% LLM, 100% me, yes, the math is correct


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import runner as scripts_runner


class ScriptsRunnerTests(unittest.TestCase):
    def test_main_exports_four_report_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            sample_path = temp_path / "sample.bin"
            output_dir = temp_path / "out"
            sample_path.write_bytes(b"zenze")

            fake_reports = {
                "hybridanalysis": {"summary": {}},
                "virustotal": {"analysis_id": "abc", "attributes": {}},
                #"radare2": {"meta": {}},
                "yara": [{"rule": "dummy"}],
            }

            with mock.patch.object(scripts_runner, "run_all", return_value=fake_reports) as mock_run_all:
                result = scripts_runner.main(
                    [
                        str(sample_path),
                        "--env-id",
                        "140",
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            mock_run_all.assert_called_once_with(
                sample_path=sample_path.resolve(),
                environment_id="140",
                # r2_bin=None,
                # r2_cmds=[],
            )

            self.assertEqual(result, 0)
            for report_name, payload in fake_reports.items():
                report_file = output_dir / f"{report_name}.json"
                self.assertTrue(report_file.exists())
                self.assertEqual(json.loads(report_file.read_text(encoding="utf-8")), payload)


if __name__ == "__main__":
    unittest.main()