import argparse
from pathlib import Path


def _default_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data"


# You guessed it, LLMs
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="[zense] Run all analyzers and export JSON reports")

    parser.add_argument(
        "sample",   # the urge to name this 'patient'
        type=Path,
        help="Path to target malware sample")

    parser.add_argument(
        "--anyrun-task-uuid",
        required=True,
        help="Existing ANY.RUN task UUID")

    parser.add_argument(
        "--r2-bin",     # --path-to-r2 sounds better but is long.
        default=None,
        help="Path to radare2 binary (defaults to auto-detect)")

    parser.add_argument(
        "--r2-cmd",
        dest="r2_cmds",
        action="append",
        default=[],
        help="Extra radare2 command (repeatable)",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_default_output_dir(),
        help="Directory for exported JSON")

    return parser
