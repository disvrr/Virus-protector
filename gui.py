import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import heuristics
import quarantine
import scanner


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Virus Protector")
        root.geometry("900x500")
        self.q: "queue.Queue" = queue.Queue()
        self.path = tk.StringVar()
        self.status = tk.StringVar(value="Ready")

        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")
        ttk.Entry(top, textvariable=self.path).pack(side="left", fill="x", expand=True)
        ttk.Button(top, text="Browse...", command=self.browse).pack(side="left", padx=4)
        ttk.Button(top, text="Scan", command=self.start_scan).pack(side="left")

        cols = ("file", "method", "details")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="extended")
        for col, title, width in zip(cols, ("File", "Method", "Details"), (350, 90, 440)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True, padx=8)

        bottom = ttk.Frame(root, padding=8)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Quarantine selected", command=self.isolate).pack(side="left")
        ttk.Button(bottom, text="Quarantine...", command=self.show_quarantine).pack(side="left", padx=4)
        ttk.Label(bottom, textvariable=self.status).pack(side="right")
        self.poll()

    def browse(self):
        d = filedialog.askdirectory()
        if d:
            self.path.set(d)

    def start_scan(self):
        if not self.path.get():
            messagebox.showwarning("Antivirus", "Select a directory")
            return
        self.tree.delete(*self.tree.get_children())
        self.status.set("Scanning...")
        threading.Thread(target=self.worker, args=(self.path.get(),), daemon=True).start()

    def worker(self, path):
        db = scanner.load_signatures()
        n = 0
        for p in scanner.iter_files(path):
            n += 1
            det = scanner.scan_file(p, db)
            if det:
                self.q.put(("hit", str(p), "Signature", det.reason))
            else:
                res = heuristics.analyze_file(p)
                if res.score >= 30:
                    self.q.put(("hit", str(p), "Heuristic",
                                f"{res.verdict} ({res.score}): " + "; ".join(res.reasons)))
            if n % 50 == 0:
                self.q.put(("progress", n))
        self.q.put(("done", n))

    def poll(self):
        try:
            while True:
                kind, *data = self.q.get_nowait()
                if kind == "hit":
                    self.tree.insert("", "end", values=tuple(data))
                elif kind == "progress":
                    self.status.set(f"Files scanned: {data[0]}")
                elif kind == "done":
                    self.status.set(f"Done. Files scanned: {data[0]}, detections: {len(self.tree.get_children())}")
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def isolate(self):
        for item in self.tree.selection():
            path, method, details = self.tree.item(item, "values")
            try:
                quarantine.quarantine_file(path, f"{method}: {details}")
                self.tree.delete(item)
            except OSError as e:
                messagebox.showerror("Error", f"{path}\n{e}")

    def show_quarantine(self):
        win = tk.Toplevel(self.root)
        win.title("Quarantine")
        win.geometry("700x300")
        tree = ttk.Treeview(win, columns=("id", "path", "reason"), show="headings")
        for col, title in zip(("id", "path", "reason"), ("ID", "Original path", "Reason")):
            tree.heading(col, text=title)
        tree.pack(fill="both", expand=True, padx=8, pady=8)

        def refresh():
            tree.delete(*tree.get_children())
            for qid, e in quarantine.list_items().items():
                tree.insert("", "end", values=(qid, e["original_path"], e["reason"]))

        def act(func):
            for item in tree.selection():
                func(tree.item(item, "values")[0])
            refresh()

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(bar, text="Restore", command=lambda: act(quarantine.restore)).pack(side="left")
        ttk.Button(bar, text="Delete", command=lambda: act(quarantine.delete)).pack(side="left", padx=4)
        refresh()


def run():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    run()
