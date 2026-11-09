#!/usr/bin/env python3
import argparse
import sys

import heuristics
import integrity
import process_monitor
import quarantine
import scanner
from logger import get_logger

log = get_logger()


def _isolate(path, reason, sha256="") -> None:
    try:
        qid = quarantine.quarantine_file(path, reason, sha256)
        print(f"  -> moved to quarantine (id={qid})")
    except OSError as e:
        log.error("Could not quarantine %s: %s", path, e)


def cmd_scan(args) -> int:
    db = scanner.load_signatures()
    stats = {"files": 0}
    found = list(scanner.scan_path(args.path, db, stats))
    for det in found:
        log.warning("DETECTED: %s - %s", det.path, det.reason)
        if args.quarantine:
            _isolate(det.path, det.reason, det.sha256)
    print(f"Files scanned: {stats['files']}, threats: {len(found)}")
    return 1 if found else 0


def cmd_heur(args) -> int:
    count = 0
    for res in heuristics.analyze_path(args.path, args.min_score):
        count += 1
        log.warning("%s: %s (score %d)", res.verdict.upper(), res.path, res.score)
        for reason in res.reasons:
            print("    " + reason)
        if args.quarantine and res.score >= 60:
            _isolate(res.path, f"heuristic: {res.score} points")
    print(f"Files with score >= {args.min_score}: {count}")
    return 1 if count else 0


def cmd_full(args) -> int:
    args.min_score = 30
    return max(cmd_scan(args), cmd_heur(args))


def cmd_baseline(args) -> int:
    n = integrity.build_baseline(args.path, args.baseline)
    print(f"Baseline created, files: {n}")
    return 0


def cmd_check(args) -> int:
    diff = integrity.check_baseline(args.path, args.baseline)
    total = sum(len(v) for v in diff.values())
    print(f"Modified: {len(diff['modified'])}, deleted: {len(diff['deleted'])}, new: {len(diff['new'])}")
    return 1 if total else 0


def cmd_watch(args) -> int:
    integrity.watch(args.path, args.baseline)
    return 0


def cmd_procs(args) -> int:
    if args.watch:
        process_monitor.monitor_processes(duration=args.watch)
        return 0
    findings = process_monitor.scan_processes()
    for f in findings:
        log.warning("PID=%s %s - %s", f.pid, f.name, f.reason)
    print(f"Suspicious processes: {len(findings)}")
    return 1 if findings else 0


def cmd_autorun(args) -> int:
    entries = process_monitor.scan_autorun()
    bad = 0
    for e in entries:
        mark = "!!" if e.suspicious else "ok"
        print(f"[{mark}] {e.location} | {e.name} | {e.command}" + (f"  <- {e.reason}" if e.reason else ""))
        bad += e.suspicious
    print(f"Entries: {len(entries)}, suspicious: {bad}")
    return 1 if bad else 0


def cmd_qlist(args) -> int:
    items = quarantine.list_items()
    if not items:
        print("Quarantine is empty")
    for qid, e in items.items():
        print(f"{qid} | {e['date']} | {e['original_path']} | {e['reason']}")
    return 0


def cmd_qrestore(args) -> int:
    print("Restored:", quarantine.restore(args.id))
    return 0


def cmd_qdelete(args) -> int:
    quarantine.delete(args.id)
    print("Deleted from quarantine")
    return 0


def cmd_addsig(args) -> int:
    print("Hash added:", scanner.add_signature(args.file, args.name))
    return 0


def cmd_gui(args) -> int:
    import gui
    gui.run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="antivirus", description="Educational antivirus toolkit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_text, path=False, quar=False, baseline=False):
        p = sub.add_parser(name, help=help_text)
        if path:
            p.add_argument("path", help="file or directory")
        if quar:
            p.add_argument("-q", "--quarantine", action="store_true", help="quarantine detected files")
        if baseline:
            p.add_argument("-b", "--baseline", default=str(integrity.DEFAULT_BASELINE), help="baseline file")
        p.set_defaults(func=func)
        return p

    add("scan", cmd_scan, "signature scan", path=True, quar=True)
    h = add("heur", cmd_heur, "heuristic analysis", path=True, quar=True)
    h.add_argument("--min-score", type=int, default=30, help="minimum score to report")
    add("full", cmd_full, "signature and heuristic scan", path=True, quar=True)
    add("baseline", cmd_baseline, "create an integrity baseline", path=True, baseline=True)
    add("check", cmd_check, "check integrity against the baseline", path=True, baseline=True)
    add("watch", cmd_watch, "monitor a directory in real time", path=True, baseline=True)
    pr = add("procs", cmd_procs, "scan processes")
    pr.add_argument("--watch", type=float, metavar="SECONDS", help="monitor new processes for N seconds")
    add("autorun", cmd_autorun, "scan startup entries (Windows)")
    add("qlist", cmd_qlist, "list quarantined files")
    q = add("qrestore", cmd_qrestore, "restore a quarantined file")
    q.add_argument("id")
    q = add("qdelete", cmd_qdelete, "delete a quarantined file")
    q.add_argument("id")
    s = add("addsig", cmd_addsig, "add a file hash to the signature database")
    s.add_argument("file")
    s.add_argument("name")
    add("gui", cmd_gui, "launch the graphical interface")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, KeyError, RuntimeError) as e:
        log.error("%s", e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
