import json
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

from logger import get_logger

log = get_logger()

QUARANTINE_DIR = Path(__file__).resolve().parent / "quarantine"
_XOR_KEY = 0x5A
_TABLE = bytes(b ^ _XOR_KEY for b in range(256))
_CHUNK = 1024 * 1024


def _index_file() -> Path:
    return QUARANTINE_DIR / "index.json"


def _load_index() -> Dict[str, dict]:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    f = _index_file()
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    return {}


def _save_index(index: Dict[str, dict]) -> None:
    _index_file().write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")


def _xor_copy(src: Path, dst: Path) -> None:
    """XOR is symmetric: the same function both encodes and decodes."""
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            fout.write(chunk.translate(_TABLE))


def quarantine_file(path, reason: str = "", sha256: str = "") -> str:
    """Move a file to quarantine and return its entry ID."""
    src = Path(path).resolve()
    index = _load_index()
    qid = uuid.uuid4().hex[:12]
    dst = QUARANTINE_DIR / f"{qid}.quar"
    _xor_copy(src, dst)
    try:
        src.unlink()
    except OSError:
        dst.unlink()
        raise
    index[qid] = {
        "original_path": str(src),
        "reason": reason,
        "sha256": sha256,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_index(index)
    log.info("Quarantined: %s -> %s (%s)", src, dst.name, reason)
    return qid


def list_items() -> Dict[str, dict]:
    return _load_index()


def restore(qid: str, dest: Optional[str] = None) -> Path:
    """Restore a file. If the destination exists, append the .restored suffix."""
    index = _load_index()
    if qid not in index:
        raise KeyError(f"No quarantine entry: {qid}")
    entry = index[qid]
    target = Path(dest or entry["original_path"])
    if target.exists():
        target = target.with_name(target.name + ".restored")
    target.parent.mkdir(parents=True, exist_ok=True)
    qfile = QUARANTINE_DIR / f"{qid}.quar"
    _xor_copy(qfile, target)
    qfile.unlink()
    del index[qid]
    _save_index(index)
    log.info("Restored from quarantine: %s", target)
    return target


def delete(qid: str) -> None:
    """Permanently delete a file from quarantine."""
    index = _load_index()
    if qid not in index:
        raise KeyError(f"No quarantine entry: {qid}")
    qfile = QUARANTINE_DIR / f"{qid}.quar"
    if qfile.exists():
        qfile.unlink()
    del index[qid]
    _save_index(index)
    log.info("Deleted from quarantine: %s", qid)
