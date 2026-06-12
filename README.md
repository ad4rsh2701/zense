# zense 

Automated Malware Analytics Aggregator.

Script `scripts/runner.py` _orchestrates_ the existing analyzers (ANY.RUN, VirusTotal, radare2, and YARA)
and exports 4 JSON reports.

> `zense` does not analyze the malware directly nor does it ever run it.  
> However, running `zense` inside a VM is recommended. Please handle your malware samples carefully!

## What gets exported

By default, reports are exported to `data/`:

- `data/anyrun.json`
- `data/virustotal.json`
- `data/radare2.json`
- `data/yara.json`

## Requirements
- Python 3.12+
- Dependencies from `requirements.txt`
- radare2 installed and available in `PATH` (or pass install path via `--r2-bin`)
- Internet access for ANY.RUN and VirusTotal API calls (obv)
- ANY.RUN UUID after uploading the malware sample on [any.run](https://any.run/)
- A `.env` file in project root with:
```env
AR_KEY=your_anyrun_api_key
VT_KEY=your_virustotal_api_key
```

## Setup
```shell
python -m pip install -r requirements.txt
```

## Usage
```powershell
python scripts\runner.py <sample_path> --anyrun-task-uuid <anyrun_task_uuid>
```

### Examples
Run with default output directory (`data/`):

```powershell
python scripts\runner.py .\samples\test.bin --anyrun-task-uuid 00000
```

Run with custom output directory:

```powershell
python scripts\runner.py .\samples\test.bin --anyrun-task-uuid 00000 --output-dir .\data\reports
```

Run with extra radare2 commands:

```powershell
python scripts\runner.py .\samples\test.bin --anyrun-task-uuid 00000 --r2-cmd af --r2-cmd ii
```

## Current Limitations
- ANY.RUN integration currently fetches reports for an **existing task UUID**; this runner does not submit new tasks
- The report by ANY.RUN is a basic report (must not be used for Dynamic Analysis directly)
- ANY.RUN file-size is limited to **16 MB** (I am a free tier minion)
- VirusTotal polling is made slow intentionally (120s interval), so runs may take several minutes.
- Output schemas are mostly passthrough from upstream tools/APIs and can change when those services change.
- YARA rules are compiled from `data/yara-signatures/yara`; missing or invalid rule files will break YARA or provide inaccurate analysis.
