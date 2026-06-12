from pathlib import Path
from typing import Any

# my modules
from core.parser import build_parser
from core.exporter import export_reports


def _run_anyrun(task_uuid: str, file_bytes: bytes) -> dict[str, Any]:
    from anyrun import runner as anyrun_runner

    ioc, summary = anyrun_runner.run(task_uuid, file_bytes)
    return {
        "ioc": ioc,
        "summary": summary,
    }


def _run_virustotal(file_bytes: bytes, filename: str) -> dict[str, Any]:
    from virustotal import runner as vt_runner

    return vt_runner.run(file_bytes, filename=filename)


def _run_radare2(sample_path: Path, r2_bin: str | None, extra_cmds: list[str]) -> dict[str, Any]:
    from radare2 import runner as r2_runner

    resolved_r2 = r2_bin or r2_runner.where_r2()
    return r2_runner.run(resolved_r2, sample_path, extra_cmds)


def _run_yara(file_bytes: bytes) -> list[dict[str, Any]]:
    from yarazense import runner as yara_runner

    return yara_runner.run(file_bytes)


def run_all(sample_path: Path, anyrun_task_uuid: str, r2_bin: str | None, r2_cmds: list[str]) -> dict[str, Any]:
    file_bytes = sample_path.read_bytes()

    print("[zense] Running ANY.RUN runner...")
    anyrun_report = _run_anyrun(anyrun_task_uuid, file_bytes)

    print("[zense] Running VirusTotal runner...")
    virustotal_report = _run_virustotal(file_bytes, sample_path.name)

    print("[zense] Running radare2 runner...")
    radare2_report = _run_radare2(sample_path, r2_bin, r2_cmds)

    print("[zense] Running YARA runner...")
    yara_report = _run_yara(file_bytes)

    return {
        "anyrun": anyrun_report,
        "virustotal": virustotal_report,
        "radare2": radare2_report,
        "yara": yara_report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sample_path = args.sample.resolve()
    if not sample_path.is_file():
        raise FileNotFoundError(f"[zense] Sample does not exist: {sample_path}")

    reports = run_all(
        sample_path=sample_path,
        anyrun_task_uuid=args.anyrun_task_uuid,
        r2_bin=args.r2_bin,
        r2_cmds=args.r2_cmds,
    )
    exported = export_reports(args.output_dir.resolve(), reports)

    print(f"[zense] Done. Exported {len(exported)} JSON reports to: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
