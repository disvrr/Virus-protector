import json
import time
from pathlib import Path

from logger import get_logger
from scanner import file_hash, iter_files

log = get_logger()

DEFAULT_BASELINE = Path(__file__).resolve().parent / "baseline.json"


def _snapshot(root) -> dict:
    root = Path(root).resolve()
    base = root.parent if root.is_file() else root
    files = {}
    for p in iter_files(root):
        try:
            files[p.resolve().relative_to(base).as_posix()] = {
                "sha256": file_hash(p),
                "size": p.stat().st_size,
            }
        except OSError as e:
            log.warning("Skipped %s: %s", p, e)
    return files


def build_baseline(root, baseline_file=DEFAULT_BASELINE) -> int:
    """Create a baseline and return the number of files."""
    files = _snapshot(root)
    data = {
        "root": str(Path(root).resolve()),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files": files,
    }
    Path(baseline_file).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("Baseline created: %d files (%s)", len(files), baseline_file)
    return len(files)


def check_baseline(root, baseline_file=DEFAULT_BASELINE) -> dict:
    """Compare the current state with the baseline."""
    saved = json.loads(Path(baseline_file).read_text(encoding="utf-8"))["files"]
    current = _snapshot(root)
    modified = sorted(k for k in saved if k in current and saved[k]["sha256"] != current[k]["sha256"])
    deleted = sorted(k for k in saved if k not in current)
    new = sorted(k for k in current if k not in saved)
    for k in modified:
        log.warning("[INTEGRITY] Modified: %s", k)
    for k in deleted:
        log.warning("[INTEGRITY] Deleted: %s", k)
    for k in new:
        log.warning("[INTEGRITY] New file: %s", k)
    return {"modified": modified, "deleted": deleted, "new": new}


def watch(root, baseline_file=DEFAULT_BASELINE) -> None:
    """Monitor in real time (requires the watchdog package). Stop with Ctrl+C."""
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        raise RuntimeError("Install watchdog: pip install watchdog")

    root = Path(root).resolve()
    known = json.loads(Path(baseline_file).read_text(encoding="utf-8"))["files"]

    def rel(p):
        try:
            return Path(p).resolve().relative_to(root).as_posix()
        except ValueError:
            return None

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                log.warning("[INTEGRITY] File created: %s", event.src_path)

        def on_modified(self, event):
            if event.is_directory:
                return
            key = rel(event.src_path)
            if key in known:
                try:
                    if file_hash(event.src_path) != known[key]["sha256"]:
                        log.warning("[INTEGRITY] File modified: %s", event.src_path)
                except OSError:
                    pass

        def on_deleted(self, event):
            if not event.is_directory and rel(event.src_path) in known:
                log.warning("[INTEGRITY] File deleted: %s", event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                log.warning("[INTEGRITY] File renamed: %s -> %s", event.src_path, event.dest_path)

    observer = Observer()
    observer.schedule(Handler(), str(root), recursive=True)
    observer.start()
    log.info("Monitoring %s (press Ctrl+C to stop)", root)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
