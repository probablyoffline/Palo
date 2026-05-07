# get-rule-traffic-logs

Queries the PAN-OS traffic log API for each rule in an input file and writes all matching log entries to per-rule CSV files in an output directory.

## Prerequisites

Set `MODE`, `VSYS`, and `DEVICE_GROUP` in `ops_lib.py` to match your environment before running.

## Usage

```
python get-rule-traffic-logs.py <input_file> [options]
python get-rule-traffic-logs.py -h
```

`-h` / `--help` prints the built-in argument reference and exits.

`<input_file>` is a `.txt` or `.csv` file of rule names, one per line — the same format used by the other Ops scripts (e.g. `test-list.txt`).

## Flags

### Time period (mutually exclusive)

| Flag | Description |
|------|-------------|
| `--days N` | Pull logs from the last N days (default: **30**) |
| `--start DATETIME` | Start of an explicit time range |
| `--end DATETIME` | End of an explicit time range; only valid with `--start` (default: now) |

Datetime format: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`.

`--days` and `--start` cannot be used together.

### Other options

| Flag | Description |
|------|-------------|
| `--action allow\|deny\|drop\|all` | Filter entries by action (default: **all**) |
| `--output-dir PATH` / `-o PATH` | Directory for output CSVs (default: `traffic-logs-YYYYMMDD-HHMMSS`) |
| `--max-logs N` | Max entries per rule, 1–5000 (default: **5000**) |

## Output

One CSV per rule is written to the output directory. The filename is derived from the rule name with non-alphanumeric characters replaced by underscores, plus a timestamp suffix:

```
<rule-name>-YYYYMMDD-HHMMSS.csv
```

Rules that return no traffic produce no file. The run prints a summary showing counts of rules with traffic, no traffic, capped results, and errors.

### Status values printed per rule

| Status | Meaning |
|--------|---------|
| `ok` | Entries returned, below the cap |
| `ok (capped)` | Cap was hit; results may be incomplete — rerun with a narrower time range or lower `--max-logs` |
| `no_traffic` | Query succeeded but zero entries matched |
| `timeout` | Job did not finish within 120 seconds |
| `error: <msg>` | Submission or network failure |

## Examples

Last 30 days (default), all actions:
```
python get-rule-traffic-logs.py rules.txt
```

Last 7 days, denied traffic only:
```
python get-rule-traffic-logs.py rules.txt --days 7 --action deny
```

Explicit date range, output to a named directory:
```
python get-rule-traffic-logs.py rules.txt --start 2026-04-01 --end 2026-04-30 -o april-logs
```

Exact datetime range:
```
python get-rule-traffic-logs.py rules.txt --start "2026-05-01 08:00:00" --end "2026-05-01 17:00:00"
```
