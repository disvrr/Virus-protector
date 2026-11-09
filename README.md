# Virus Protector

Virus Protector is an educational antivirus toolkit written in Python. It combines
signature-based scanning with heuristic analysis and includes quarantine,
integrity monitoring, process inspection, startup-entry checks, and a graphical
interface.

## Features

- **Signature scanning:** compares file SHA-256 hashes and searches for byte
  patterns in the first 1 MiB of each file.
- **Heuristic analysis:** assigns scores for suspicious characteristics such as
  double extensions, executable files in user-writable locations, high entropy,
  and suspicious strings.
- **Quarantine:** moves detected files into a local quarantine directory. Files
  are XOR-obfuscated while stored; this is not secure encryption.
- **Integrity checks:** creates and compares file-hash baselines, with optional
  real-time monitoring for file changes.
- **Process and startup inspection:** checks running processes and Windows
  startup entries.
- **GUI:** provides file scanning and quarantine management through Tkinter.

This project is intended for educational use. Its signature database is small,
and its heuristic results can include false positives or miss threats. It is
not a replacement for a maintained commercial antivirus product.

## Requirements

- Python 3
- Tkinter for the graphical interface (usually included with standard Python
  installations)
- Optional: `psutil` for process scanning and monitoring
- Optional: `watchdog` for real-time integrity monitoring

Install optional packages with:

```powershell
py -m pip install psutil watchdog
```

Run commands from the project directory:

```powershell
py .\main.py --help
```

## Usage

### Scan files

Scan a file or directory against the signature database:

```powershell
py .\main.py scan "C:\path\to\file-or-directory"
```

Add `-q` to quarantine signature detections:

```powershell
py .\main.py scan "C:\path\to\directory" -q
```

Run heuristic analysis (the default reporting threshold is 30):

```powershell
py .\main.py heur "C:\path\to\directory"
py .\main.py heur "C:\path\to\directory" --min-score 40
```

With `-q`, heuristic analysis quarantines files only when their score is 60 or
higher:

```powershell
py .\main.py heur "C:\path\to\directory" -q
```

Run both signature scanning and heuristic analysis:

```powershell
py .\main.py full "C:\path\to\directory"
```

### Manage the quarantine

List, restore, or permanently delete quarantined files using the ID printed by
the application:

```powershell
py .\main.py qlist
py .\main.py qrestore <id>
py .\main.py qdelete <id>
```

Quarantine data and its index are stored in the project's `quarantine` folder.
Restoring a file whose original path is already occupied writes it with a
`.restored` suffix.

### Manage signatures

Add the SHA-256 hash of a file to `signatures.json`:

```powershell
py .\main.py addsig "C:\path\to\file" "Signature name"
```

Only add hashes for files you have intentionally verified. A hash entry
identifies an exact file content; it is not a general malware-family detector.

### Check file integrity

Create a baseline for a file or directory, then compare the current contents
against it:

```powershell
py .\main.py baseline "C:\path\to\directory"
py .\main.py check "C:\path\to\directory"
```

The default baseline file is `baseline.json` in the project directory. Use
`-b` to select a different baseline file:

```powershell
py .\main.py baseline "C:\path\to\directory" -b "C:\path\to\baseline.json"
py .\main.py check "C:\path\to\directory" -b "C:\path\to\baseline.json"
```

Monitor a directory for changes relative to an existing baseline:

```powershell
py .\main.py watch "C:\path\to\directory"
```

Press `Ctrl+C` to stop monitoring. The optional `watchdog` package is required.

### Inspect processes and startup entries

These commands are intended for Windows. Process inspection requires `psutil`.

```powershell
py .\main.py procs
py .\main.py procs --watch 60
py .\main.py autorun
```

The `--watch` value is the number of seconds to monitor for newly started
processes.

### Launch the GUI

```powershell
py .\main.py gui
```

## Tests

Run the unit tests from the project directory:

```powershell
py -m unittest discover -s tests -v
```

## Logging

Application logs are written to `antivirus.log` in the project directory and
also displayed in the console.
