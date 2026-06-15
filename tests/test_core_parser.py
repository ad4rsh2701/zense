import sys
import unittest
from pathlib import Path

# 90% LLM, 10% me, go figure out yourself

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.parser import build_parser


class ParserTests(unittest.TestCase):
    def test_parser_sets_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["sample.bin", "--env-id", "120"])

        self.assertEqual(args.sample, Path("sample.bin"))
        self.assertEqual(args.env_id, "120")
        # self.assertEqual(args.r2_cmds, [])
        # self.assertIsNone(args.r2_bin)
        self.assertEqual(args.out_dir.name, "data")

if __name__ == "__main__":
    unittest.main()