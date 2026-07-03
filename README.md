# AmcacheParser Wrapper

A single-file, double-clickable GUI for triaging the **Windows Amcache** (`Amcache.hve`) with [Eric Zimmerman's AmcacheParser](https://ericzimmerman.github.io/) — built for DFIR casework.

No install, no dependencies, no framework: one `.hta` file that runs on any Windows box via the built-in `mshta.exe`. Point it at a collected `Amcache.hve`, a whole KAPE/Velociraptor collection folder, or snapshot the live machine's hive, and it runs AmcacheParser for you and turns all eight output CSVs into an interactive, suspicion-scored triage view.

Sibling of [PECmd-Wrapper](https://github.com/bpmorris22/PECmd-Wrapper), [SrumECmd-Wrapper](https://github.com/bpmorris22/SrumECmd-Wrapper) and [SQLECmd-Wrapper](https://github.com/bpmorris22/SQLECmd-Wrapper) — same tooling, same viewer, deliberately complementary artifacts: Amcache carries **SHA1 + compile date + publisher metadata** that prefetch lacks; prefetch carries the run counts and timestamps that Amcache lacks.

## Features

- **Runs AmcacheParser for you** — `-i` (associated file entries) and `--nl` (skip transaction-log replay) switches, output to timestamped CSVs, asynchronously in a visible console so the UI never freezes.
- **Finds the hive for you** — point the input at a collection folder and it recursively locates `Amcache.hve` (URL-encoded Velociraptor paths like `C%3A` work as-is); multiple hives found → pick from a list.
- **Snapshot the live machine** — the live hive is locked while Windows runs; one button copies it (plus both transaction logs) with `esentutl /y /vss` into a `LiveSnapshot` folder and parses the copy. Requires an elevated run — the app tells you when it isn't.
- **Self-managing tooling** — finds `AmcacheParser.exe` next to the `.hta` (or in `C:\ZimmermanTools`), checks the live latest version, and can download/update a self-contained copy with one click. Sets `DOTNET_ROLL_FORWARD=Major` automatically.
- **Three views of one run**:
  - **File entries** — Unassociated + Associated CSVs merged, one row per binary: full path, first-seen, compile date (LinkDate), SHA1, size, product, and the publisher/install-date joined from the run's ProgramEntries via ProgramId.
  - **Programs** — one row per installed-program entry with best-of install date, root dir, and per-program file counts; the detail pane lists a program's file entries with one-click pivot back to the File-entries view.
  - **Drivers** — one row per driver binary, **unsigned kernel-mode drivers sorted first**.
- **Suspicion scoring** tuned on real incident data (table below). Suspicious rows are shaded; every tag shows its reasoning on hover.
- **IOC / keyword list with SHA1 support** — paste or load terms; **40-hex tokens are matched as SHA1 hashes** (exact) against every file entry, everything else as a case-insensitive substring across names, paths, products, publishers, programs and ProgramIds. Matches rescore live (+3). Paste hashes straight from a threat-intel report.
- **Detail pane** — click any row: every field, click-to-copy SHA1 (ready for VT), the linked program entry, driver signing detail.
- **Filters** — per-view category buttons with live counts, free-text search, UTC date range.
- **Reporting** — export the filtered view (any view) to CSV, or copy formatted lines straight into case notes.

## Quick start

1. Download `AmcacheParser-Wrapper.hta` into an empty folder.
2. Double-click it. If `AmcacheParser.exe` isn't found next to it, the app offers to download the latest official build from `download.ericzimmermanstools.com` into the same folder.
3. Point the input at an Amcache source and click **Process → analyze**:
   - a collected `Amcache.hve` (keep its `.LOG1`/`.LOG2` beside it — transaction logs are replayed automatically, in memory, without touching the source),
   - a KAPE / Velociraptor collection folder (the hive is found for you),
   - or click **Snapshot live Amcache** on the machine itself (elevated).
4. Or skip processing and **Load existing CSV…** — FileEntries, ProgramEntries and DriveBinaries CSVs land in their rich views (and pull in the rest of their run when the sibling CSVs are present); anything else opens in a generic sortable grid.

## Suspicion heuristics

File entries shade at score ≥ 3 — Amcache indexes every binary the compatibility scanner sees, so a bare user-path hit isn't shade-worthy on its own; combinations are the signal. Programs shade at ≥ 2; a flagged driver shades directly.

| Tag | Trigger | Score |
|---|---|---|
| `USERPATH` | Lives in a user-writable path (`\Users\`, `\AppData\`, `\Temp\`, `\Downloads\`, `\ProgramData\`, `\PerfLogs\`, `\Windows\Temp\`, `$Recycle.Bin`, `\Public\`; Defender platform and `ProgramData\Package Cache` excluded as chronic FPs) | +2 |
| `LOLBIN` | Dual-use binary (powershell, cmd, wscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, curl, node, java, python, psexec, wmic, …) | +1 (+1 more if also user-path) |
| `MASQ` | OS-binary name (svchost, lsass, explorer, …) living **outside** `\Windows\` | +3 |
| `IOC` | IOC list hit — SHA1 exact or keyword substring, anywhere in the record | +3 |
| `UNSIGNED-KMD` | *(Drivers)* kernel-mode, not inbox, not reported signed | +3 |
| `MULTI-PATH` | Same file name present under **both** system and user-writable paths (version-number path segments neutralized) | +1 |
| `RECENT` | First seen in the last 14 days **of the dataset** (anchored to the newest entry, not the clock — collections are analyzed later) | +1 |
| `NOMETA` | PE file with no product/publisher/description metadata | +1 |
| `FRESHPE` | Compiled (LinkDate) within 7 days of first-seen, in a user-writable path | +1 |
| `RANDOM` | Hex-blob or entropy-smelling file name | +1 |

## Notes & limitations

- **Amcache presence ≠ execution.** Entries are written by Microsoft's compatibility scanner and can exist for binaries that were only installed or scanned, never run. Corroborate with prefetch / SRUM before calling execution.
- **The scanner lags.** A hive's newest entry can predate known activity by weeks or months (scheduled-task cadence; often effectively disabled on servers). A quiet Amcache is not an all-clear — check the first-seen range stat.
- `FileKeyLastWriteTimestamp` approximates *first seen/scanned*, not each run; there are no run counts. SHA1 covers only the **first 30 MB** of a file.
- All timestamps are displayed **as AmcacheParser emits them: UTC**. No local-time conversion, on purpose.
- **Dirty hives:** transaction-log replay occasionally fails on collected hives (`Offset and length were out of bounds…`). The app detects this and tells you to tick **skip log replay** (`--nl`) — you lose only the newest unflushed entries.
- **Driver signing is under-reported** for some catalog-signed Microsoft drivers (Bluetooth `bth*.sys` are common `UNSIGNED-KMD` false positives). The tag's hover text reminds you to verify before calling it.
- Old-format (Windows 8-era) hives produce a reduced CSV set and open in the generic grid.
- Win10+ paths in `DriverTimeStamp` are often bogus future dates (hash stamps) — the Drivers view sorts on `DriverLastWriteTime` instead and shows the raw value only in the detail pane.
- Table display caps at 6,000 rows for responsiveness; exports always write the full filtered set.
- **Running from a network location** (mapped drive / UNC): Windows zone policy blocks the UTF-8 file reader there, so the app automatically falls back to ANSI file IO and logs a one-time note. Everything functions; rare non-ASCII characters may display incorrectly. For full fidelity run from a local path.

## Credits

- [Eric Zimmerman](https://ericzimmerman.github.io/) for AmcacheParser and the EZ Tools suite — this is an unaffiliated wrapper around his parser; all parsing credit is his.

## License

MIT License

Copyright (c) 2026 Ben Morris

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
