import math
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List

from scanner import iter_files

EXEC_EXT = {".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".ps1", ".msi", ".dll", ".jar", ".lnk", ".hta", ".cpl"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
           ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".zip", ".rar"}
PE_EXT = {".exe", ".dll", ".sys", ".scr", ".ocx", ".com", ".cpl", ".efi"}

ENTROPY_LIMIT = 7.2        
SAMPLE_SIZE = 1024 * 1024    
SUSPICIOUS_STRINGS = [
    (b"-encodedcommand", 25, "PowerShell encoded command"),
    (b"powershell -enc", 25, "PowerShell encoded command"),
    (b"frombase64string", 10, "Base64 decoding in code"),
    (b"vssadmin delete shadows", 40, "shadow copy deletion"),
    (b"wscript.shell", 10, "command execution through WScript.Shell"),
    (b"urldownloadtofile", 15, "file download from the internet"),
    (b"createremotethread", 15, "code injection into another process (CreateRemoteThread)"),
    (b"virtualallocex", 15, "memory allocation in another process (VirtualAllocEx)"),
    (b"writeprocessmemory", 15, "writing to another process's memory"),
    (b"currentversion\\run", 10, "adding itself to startup"),
]
STRINGS_CAP = 60

@dataclass
class HeuristicResult:
    path: Path
    score: int = 0
    reasons: List[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.score >= 60:
            return "likely malicious"
        if self.score >= 30:
            return "suspicious"
        return "clean"

    def add(self, points: int, why: str) -> None:
        self.score += points
        self.reasons.append(f"+{points}: {why}")


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _suspicious_dirs() -> List[str]:
    dirs = {tempfile.gettempdir(), str(Path.home() / "Downloads")}
    for var in ("TEMP", "TMP", "APPDATA"):
        value = os.environ.get(var)
        if value:
            dirs.add(value)
    return [os.path.normcase(os.path.abspath(d)) for d in dirs]


def _in_suspicious_dir(path: Path) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    return any(p.startswith(d + os.sep) for d in _suspicious_dirs())


def _is_hidden(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attrs != -1 and bool(attrs & 0x2)  # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        return False


def analyze_file(path) -> HeuristicResult:
    path = Path(path)
    res = HeuristicResult(path)
    try:
        with open(path, "rb") as f:
            sample = f.read(SAMPLE_SIZE)
    except OSError:
        return res

    ext = path.suffix.lower()
    suffixes = [s.lower() for s in path.suffixes]

    # 1. Double extension: report.pdf.exe
    if len(suffixes) >= 2 and suffixes[-1] in EXEC_EXT and suffixes[-2] in DOC_EXT:
        res.add(40, f"double extension {suffixes[-2]}{suffixes[-1]}")

    # 2. Multiple spaces before the extension: "invoice.pdf      .exe"
    if re.search(r"\s{4,}\.\w+$", path.name):
        res.add(20, "multiple spaces before the extension (filename spoofing)")

    # 3. Executable file (MZ header) disguised as another file type
    if sample.startswith(b"MZ") and ext not in PE_EXT:
        res.add(40, f"executable file (MZ header) with extension {ext or 'no extension'}")

    # 4. Executable file in a temporary folder, Downloads, or AppData
    if ext in EXEC_EXT and _in_suspicious_dir(path):
        res.add(20, "executable file in TEMP/AppData/Downloads")

    # 5. High entropy in executable files (a possible sign of packing)
    if ext in PE_EXT and len(sample) > 4096:
        entropy = shannon_entropy(sample)
        if entropy > ENTROPY_LIMIT:
            res.add(25, f"high entropy {entropy:.2f} (possibly packed or encrypted)")

    # 6. Suspicious strings and API calls
    low = sample.lower()
    strings_points = 0
    for pattern, points, why in SUSPICIOUS_STRINGS:
        if pattern in low and strings_points < STRINGS_CAP:
            strings_points += points
            res.add(points, why)

    # 7. Hidden executable file
    if ext in EXEC_EXT and _is_hidden(path):
        res.add(15, "executable file with the hidden attribute")

    return res


def analyze_path(root, min_score: int = 30) -> Iterator[HeuristicResult]:
    """Yield results only for files with a score at or above min_score."""
    for p in iter_files(root):
        res = analyze_file(p)
        if res.score >= min_score:
            yield res
