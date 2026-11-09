"""signature analysis"""
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional

import quarantine
from logger import get_logger

log = get_logger()

SIGNATURES_FILE = Path(__file__).resolve().parent / "signatures.json"
MAX_CONTENT_SCAN = 1024 * 1024  # Number of bytes from the beginning of a file to scan for signatures


@dataclass
class Detection:
    path: Path
    reason: str
    sha256: str


def file_hash(path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_signatures(db_path=SIGNATURES_FILE) -> dict:
    """Database: {"hashes": {sha256: name}, "patterns": [(name, bytes)]}."""
    with open(db_path, encoding="utf-8") as f:
        data = json.load(f)
    hashes = {h.lower(): name for h, name in data.get("hashes", {}).items()}
    patterns = [(p["name"], bytes.fromhex(p["hex"])) for p in data.get("patterns", [])]
    return {"hashes": hashes, "patterns": patterns}


def add_signature(file_path, name: str, db_path=SIGNATURES_FILE) -> str:
    """Add a file hash to the signature database."""
    digest = file_hash(file_path)
    with open(db_path, encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("hashes", {})[digest] = name
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    log.info("Added signature %s: %s", name, digest)
    return digest


def iter_files(root, exclude=None) -> Iterator[Path]:
    """Iterate over files in a directory (or yield a single file). The quarantine is skipped."""
    root = Path(root)
    if exclude is None:
        exclude = [quarantine.QUARANTINE_DIR]
    excluded = {Path(e).resolve() for e in exclude}
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(
        root, onerror=lambda e: log.warning("Access denied: %s", e)
    ):
        dirnames[:] = [d for d in dirnames if Path(dirpath, d).resolve() not in excluded]
        for name in filenames:
            yield Path(dirpath, name)


def scan_file(path, db: dict) -> Optional[Detection]:
    """Return a Detection if the file matches the database; otherwise, return None."""
    path = Path(path)
    try:
        digest = file_hash(path)
        name = db["hashes"].get(digest)
        if name:
            return Detection(path, f"Hash match: {name}", digest)
        with open(path, "rb") as f:
            head = f.read(MAX_CONTENT_SCAN)
        for pname, pattern in db["patterns"]:
            if pattern in head:
                return Detection(path, f"Signature found: {pname}", digest)
    except OSError as e:
        log.warning("Could not read %s: %s", path, e)
    return None


def scan_path(root, db: dict, stats: Optional[Dict[str, int]] = None) -> Iterator[Detection]:
    """Scan a directory; count scanned files in stats["files"]."""
    for p in iter_files(root):
        if stats is not None:
            stats["files"] = stats.get("files", 0) + 1
        det = scan_file(p, db)
        if det:
            yield det
