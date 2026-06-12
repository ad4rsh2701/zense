import sys
import unittest
from pathlib import Path

# 90% LLM, 10% me, go figure out yourself

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.parser import build_parser


class DumperParserTests(unittest.TestCase):
    def test_parser_sets_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["sample.bin", "--anyrun-task-uuid", "task-123"])

        self.assertEqual(args.sample, Path("sample.bin"))
        self.assertEqual(args.anyrun_task_uuid, "task-123")
        self.assertEqual(args.r2_cmds, [])
        self.assertIsNone(args.r2_bin)
        self.assertEqual(args.output_dir.name, "data")

    def test_parser_collects_multiple_r2_cmds(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "sample.bin",
                "--anyrun-task-uuid",
                "task-123",
                "--r2-cmd",
                "af",
                "--r2-cmd",
                "ii",
            ]
        )

        self.assertEqual(args.r2_cmds, ["af", "ii"])


if __name__ == "__main__":
    unittest.main()