import json
from pathlib import Path
from typing import Any


def export_json(payload: Any, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")

    print(f"\t[*] Exported: {output_path.name}")
    return output_path


def export_reports(output_dir: Path, reports: dict[str, Any]) -> dict[str, Path]:
    exported: dict[str, Path] = {}
    print(f"[zense] Exporting reports to '{output_dir}'...")
    for name, payload in reports.items():
        exported[name] = export_json(payload, output_dir / f"{name}.json")
    return exported