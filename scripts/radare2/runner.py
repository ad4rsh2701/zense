
# NOTE: This is a basic runner for r2. It is not meant to be a full-featured static analysis tool.
# NOTE: LLM was used heavily to make up for my, surprisingly, lack of Python skills.
#       The sections/concepts with LLM usages are labeled so.

import json
import hashlib
import subprocess
import shutil
import platform
import datetime
from pathlib import Path



# COMMAND SET
# Entry: (key_in_json, r2_command, description)
# All commands use the JSON-output variants (j suffix) where available so
# the output is machine-readable. Plain-text commands are kept as fallback
# where no JSON variant exists.
COMMANDS = [
    # Binary metadata
    ("file_info",        "ij",        "File info (format, arch, bits, OS, entrypoint)"),
    ("entry_points",     "iej",       "Entry points"),
    ("sections",         "iSj",       "Sections"),
    ("segments",         "iSSj",      "Segments"),
    ("imports",          "iij",       "Imports (external symbols)"),
    ("exports",          "iEj",       "Exports"),
    ("symbols",          "isj",       "Symbols"),
    ("libraries",        "ilj",       "Linked libraries"),
    ("relocations",      "irj",       "Relocations"),
    # Strings
    ("strings_data",     "izj",       "Strings in data section"),
    ("strings_all",      "izzj",      "Strings in whole binary"),
    # Headers & checksums
    ("checksums",        "itj",       "File hashes (md5/sha1/sha256 via r2)"),
    ("header",           "ihj",       "Header fields"),
    ("fields",           "iHj",       "Binary header fields (detailed)"),
    # Code analysis (static only, please.)
    ("functions",        "aflj",      "Analysed function list"),
    ("xrefs_from",       "axffj",     "Cross-references (from)"),
    # ...
    ("protections",      "iIj",       "Binary protections (NX, PIE, RELRO, canary…)"),
] # LLM generated boilerplate

# r2 command to run before the commands
INIT_COMMAND = "aaa"


# HELPERS

def _where_r2() -> str:
    masquerades = ["r2", "radare2", "radare2.exe", "r2.exe"]
    for name in masquerades:
        path = shutil.which(name)   # `which` doesn't work in version before Python 3.12
        if path:
            return path
    raise FileNotFoundError(
        "radare2 not found in PATH.\n"
        "Install from https://rada.re/n/radare2.html and make sure it is on PATH."
    )


def _file_hashes(path: Path) -> dict:
    """Compute MD5 / SHA-1 / SHA-256 in Python"""
    # I don't want to touch r2 whenever possible.
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    # yes, the below code is by an LLM. I never bothered to learn file handling
    # in python properly. Though I can probably code it in C... I digress.
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size_bytes": path.stat().st_size,
    }

# yes, I just accepted this for now, we probably won't need it
# (spoiler: we did need this)
def _no_window() -> dict:
    """Windows only: don't pop a console window."""
    if platform.system() == "Windows":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def _run_r2_command(r2_bin: str, target: str, command: str) -> tuple[str, str]:
    """
    Run a single r2 command on the target in quiet mode.
    Flags used:
        -n   do NOT load/run any r2rc scripts
        -Q   quiet
        -e   io.cache=true : open in copy-on-write cache (never writes to file)
        -c   command to execute, then quit
    """
    # if you didn't get it, we are trying to NOT run the binary at all
    # if you are feeling spicy, just double-click that binary you want to analyze /j
    cmd = [
        r2_bin,
        "-n",                   # no scripts
        "-Q",                   # quiet
        "-e", "io.cache=true",  # copy-on-write
        "-c", command,
        str(target),
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        **_no_window(),
    )
    return result.stdout.strip(), result.stderr.strip()
    # damn this took a while huh, I guess I have forgotten python.


def _parse_json_output(raw: str):
    """Try to parse r2 JSON output; fall back to raw string on failure."""
    # Apparently, not all commands are json compatible

    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw  # keep as plain text if r2 didn't return JSON (info is info after all)


# RUNNERS

def run(r2_bin: str, target: Path, extra_cmds: list[str]) -> dict:
    """
    Run all commands and return a structured dict.
    """
    # I hate dicts, and structs suck in python (it seems, or maybe I ain't niche enough)
    report: dict = {
        "meta": {
            "target":    str(target.resolve()),
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z", # I will trust CLION's autocomplete.
            "platform":  platform.system(),
            "r2_path":   r2_bin,
        },
        "hashes": _file_hashes(target),
        "analysis": {},
        "errors": [],
    }

    all_commands = list(COMMANDS)
    for ec in extra_cmds:
        ec = ec.strip()
        if ec:
            all_commands.append((f"extra_{ec}", ec, "User-supplied command"))

    # ================================================================================================
    # Build one big r2 session: aaa + all commands.
    # Who cares about performance? It's Python, spawning
    # more sub processes is probably not worth it.
    # session_cmds = INIT_COMMAND + "\n" + "\n".join(c for _, c, _ in all_commands)
    #
    # print(f"[zense] Starting r2 static analysis (single session)…")
    # cmd = [
    #    r2_bin,
    #    "-n",
    #    "-Q",
    #    "-e", "io.cache=true",
    #    "-c", session_cmds,
    #    str(target),
    # ]
    # result = subprocess.run(
    #    cmd,
    #    capture_output=True,
    #    text=True,
    #    **_no_window(),
    # )
    # all hail the LLMs breezing through the `subprocess` library.
    # I could never
    # if result.stderr:
    #    report["errors"].append(result.stderr.strip())
    #    # that's it... I guess? I hope?
    # Apparently and rightfully, r2 prints command outputs sequentially.
    # We will split it to match each expected JSON block (or at least try).
    # Because some commands output multi-line JSON we re-run individually only when the bulk parse fails.
    # raw_output = result.stdout

    # if not raw_output.strip():
    #    print("[!] r2 returned no output — re-running commands individually…")
    #    for key, cmd_str, _ in all_commands:
    #        stdout, stderr = run_r2_command(r2_bin, target, f"{INIT_COMMAND};{cmd_str}")
    #        report["analysis"][key] = parse_json_output(stdout)
    #        if stderr:
    #            report["errors"].append(f"{key}: {stderr}")
    # else:
        # Split on top-level JSON objects/arrays (each command outputs one)
    #    import re
    #    blocks = re.split(r'\n(?=[\[{])', raw_output.strip())
    #    for i, (key, _, _) in enumerate(all_commands):
    #        report["analysis"][key] = parse_json_output(blocks[i]) if i < len(blocks) else None
    #return report

    # NVM the LLMs got a pretty good point:
    # "The whole bulk-then-fallback approach is more complex than it's worth.
    # The cleaner design is to just always run one r2 process per command
    # it's slower but correct and simple"
    # ================================================================================================

    # Though I believe we can optimize the original approach and split very effectively
    # not viable right now tho. Leaving the codes if I need it


    total = len(all_commands)
    # I am so sorry.
    for i, (key, cmd_str, description) in enumerate(all_commands, 1):
        # for each command spawn a sub process and do:
        print(f"\t[{i}/{total}] {description} ({cmd_str})…")
        # `aaa` runs first, so functions/xrefs are available for later commands
        stdout, stderr = _run_r2_command(r2_bin, str(target), f"{COMMANDS};{cmd_str}")
        report["analysis"][key] = _parse_json_output(stdout)
        if stderr:
            report["errors"].append(f"{key}: {stderr}")

    return report