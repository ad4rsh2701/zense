# zense 

![Version](https://img.shields.io/github/v/release/ad4rsh2701/zense)

Automated Malware Analytics Aggregator.

Script `scripts/runner.py` _orchestrates_ the existing analyzers (Hybrid Analysis, VirusTotal, and YARA) and exports JSON reports for each one.

`zense` doesn't analyze the malware sample itself nor does it ever run it on the system. Even so, running `zense` inside a VM  or on an isolated
system is strongly recommended. Please handle your malware samples carefully!

> **Note on r2 Integration**  
> The `radare2` integration is currently disabled in `scripts/runner.py` and `scripts/core/parser.py` (commented out).  
> The standalone module still lives in `scripts/radare2/`. Feel free to contribute for radare2 integration (ref: #8)

## What gets reported

- `hybridanalysis.json` : Analytics from Falcon's Hybrid Analysis Sandobox API
- `virustotal.json` : Analytics from VirusTotal API
- `yara.json` : Local YARA rules matcher (uses a locally cloned rule set from [Neo23x0 Signature Base](https://github.com/Neo23x0/signature-base))

## Requirements
- Python 3.12+
- Dependencies from `requirements.txt`
- Internet access for Hybrid Analysis and VirusTotal API calls (obv)
- A Hybrid Analysis (Falcon Sandbox) account and API key from [hybrid-analysis.com](https://hybrid-analysis.com/)
- A VirusTotal API key from [virustotal.com](https://www.virustotal.com/)
- A `.env` file in project root with the following contents
```env
HA_KEY=your_hybridanalysis_api_key
VT_KEY=your_virustotal_api_key
```

## Setup
```shell
python -m pip install -r requirements.txt
```

## Usage
```shell
python scripts\runner.py <sample_path> [--env-id <hybridanalysis_environment_id>] [--output-dir <path>]
```

- `--env-id` selects the Hybrid Analysis sandbox environment. If omitted, it defaults to `140` (Windows 11). Other common values: `130` (Windows 10), `120` (Windows 7), `300` (Ubuntu 16), `310` (Ubuntu 21).

- Default export directory for reports is `./data` unless specified by `--output-dir`.

### Examples
1. Run with default output directory (`data/`) and default environment (Windows 11):

```shell
python scripts\runner.py .\samples\test.bin
```

2. Run targeting a specific Hybrid Analysis environment:

```shell
python scripts\runner.py .\samples\test.bin --env-id 130
```

3. Run with a custom output directory:

```shell
python scripts\runner.py .\samples\test.bin --env-id 140 --output-dir .\data\reports
```

### Testing

You can test the scripts by running the following from the project root.

```shell
python -m unittest discover -s tests -p "test_*.py"
```

## Current Limitations
- Hybrid Analysis submissions are polled for up to 5 minutes; longer-running analyses will raise a timeout.
- Hybrid Analysis file-size is limited to **250 MB** by the public Falcon Sandbox API.
- VirusTotal polling is made slow intentionally (120 s interval), so runs may take several minutes.
- Output schemas are mostly passthrough from upstream tools/APIs and can change when those services change.
- YARA rules are compiled from `data/yara-signatures/yara`; missing or invalid rule files will break YARA or provide inaccurate analysis.
- The `radare2` static analysis integration is currently disabled in the orchestrator.
