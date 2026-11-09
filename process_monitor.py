import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from logger import get_logger

try:
    import psutil
except ImportError: # psutil is optional for the other modules
    psutil = None

log = get_logger()

SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")
SYSTEM32 = os.path.join(SYSROOT, "System32")

# System processes and the directories they are expected to run from.
EXPECTED_DIRS = {
    "svchost.exe": SYSTEM32, "lsass.exe": SYSTEM32, "csrss.exe": SYSTEM32,
    "winlogon.exe": SYSTEM32, "services.exe": SYSTEM32, "smss.exe": SYSTEM32,
    "wininit.exe": SYSTEM32, "taskhostw.exe": SYSTEM32, "explorer.exe": SYSROOT,
}
SUSPICIOUS_PATH_PARTS = ("\\appdata\\local\\temp\\", "\\temp\\", "\\downloads\\",
                         "\\$recycle.bin\\", "\\users\\public\\")
SUSPICIOUS_COMMANDS = ("-encodedcommand", " -enc ", "mshta", "wscript", "cscript",
                       "http://", "https://")
SCRIPT_EXT = {".vbs", ".js", ".bat", ".cmd", ".ps1", ".exe", ".hta", ".scr"}


@dataclass
class Finding:
    pid: int
    name: str
    exe: str
    reason: str


@dataclass
class AutorunEntry:
    location: str
    name: str
    command: str
    suspicious: bool
    reason: str = ""


def _require_psutil() -> None:
    if psutil is None:
        raise RuntimeError("Install psutil: pip install psutil")


def check_process(name: Optional[str], exe: Optional[str]) -> List[str]:
    """Return reasons why a process looks suspicious."""
    reasons: List[str] = []
    if not exe:
        return reasons
    exe_norm = os.path.normcase(exe)
    expected = EXPECTED_DIRS.get((name or "").lower())
    if expected and os.path.normcase(os.path.dirname(exe)) != os.path.normcase(expected):
        reasons.append(f"impersonating system process {name}: running from {os.path.dirname(exe)}")
    if any(part in exe_norm for part in SUSPICIOUS_PATH_PARTS):
        reasons.append("running from a temporary or user directory")
    return reasons


def scan_processes() -> List[Finding]:
    """Scan all running processes once."""
    _require_psutil()
    findings = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        info = proc.info
        for reason in check_process(info.get("name"), info.get("exe")):
            findings.append(Finding(info["pid"], info.get("name") or "?", info.get("exe") or "", reason))
    return findings


def monitor_processes(interval: float = 2.0, duration: Optional[float] = None,
                      callback: Optional[Callable[[Finding], None]] = None) -> None:
    """Monitor for new processes. Stops with Ctrl+C or after duration expires."""
    _require_psutil()
    seen = {p.pid for p in psutil.process_iter()}
    started = time.time()
    log.info("Process monitoring started")
    try:
        while duration is None or time.time() - started < duration:
            time.sleep(interval)
            current = set()
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                info = proc.info
                current.add(info["pid"])
                if info["pid"] in seen:
                    continue
                log.info("New process: PID=%s %s (%s)", info["pid"], info.get("name"), info.get("exe"))
                for reason in check_process(info.get("name"), info.get("exe")):
                    finding = Finding(info["pid"], info.get("name") or "?", info.get("exe") or "", reason)
                    log.warning("SUSPICIOUS PROCESS: PID=%s %s - %s", finding.pid, finding.name, reason)
                    if callback:
                        callback(finding)
            seen = current
    except KeyboardInterrupt:
        pass


def _check_command(command: str) -> str:
    expanded = " " + os.path.expandvars(command).lower() + " "
    if any(part in expanded for part in SUSPICIOUS_PATH_PARTS):
        return "running from a temporary or user directory"
    if any(token in expanded for token in SUSPICIOUS_COMMANDS):
        return "script interpreter, encoded command, or network address"
    return ""


def scan_autorun() -> List[AutorunEntry]:
    """Check the registry Run/RunOnce keys and the Startup folder."""
    if os.name != "nt":
        log.warning("Startup scanning is available only on Windows")
        return []
    import winreg

    entries: List[AutorunEntry] = []
    hives = [("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)]
    subkeys = [r"Software\Microsoft\Windows\CurrentVersion\Run",
               r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]
    for hive_name, hive in hives:
        for subkey in subkeys:
            try:
                key = winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            with key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    reason = _check_command(str(value))
                    entries.append(AutorunEntry(f"{hive_name}\\{subkey}", name, str(value), bool(reason), reason))

    startup = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"
    if startup.is_dir():
        for item in startup.iterdir():
            if item.name.lower() == "desktop.ini":
                continue
            bad = item.suffix.lower() in SCRIPT_EXT
            entries.append(AutorunEntry("Startup folder", item.name, str(item), bad,
                                        "script or executable in Startup" if bad else ""))
    return entries
