"""Окна сообщений помощника (tkinter): всплывающее, главное с кнопками, экран «компьютер потерян»."""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import font as tkfont

BG = "#1f2328"
FG = "#f6f5f1"
ACCENT = "#6fbfa5"
WARN = "#e2a24e"


class UI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.toast: tk.Toplevel | None = None
        self.modal: tk.Toplevel | None = None
        self.lost: tk.Toplevel | None = None
        base = tkfont.nametofont("TkDefaultFont").actual()["family"]
        self.f_text = (base, 12)
        self.f_title = (base, 14, "bold")
        self.f_big = (base, 28, "bold")

    def _close(self, attr: str) -> None:
        w = getattr(self, attr)
        if w is not None:
            try:
                w.destroy()
            except tk.TclError:
                pass
            setattr(self, attr, None)

    def show_toast(self, text: str, color: str = WARN, seconds: int = 12) -> None:
        self._close("toast")
        w = tk.Toplevel(self.root)
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.configure(bg=BG, highlightthickness=2, highlightbackground=color)
        tk.Label(w, text=text, bg=BG, fg=FG, font=self.f_text, wraplength=360, justify="left",
                 padx=18, pady=14).pack()
        w.update_idletasks()
        sw, sh = w.winfo_screenwidth(), w.winfo_screenheight()
        w.geometry(f"+{sw - w.winfo_width() - 24}+{sh - w.winfo_height() - 72}")
        w.bind("<Button-1>", lambda e: self._close("toast"))
        self.toast = w
        self.root.after(seconds * 1000, lambda: self.toast is w and self._close("toast"))

    def show_modal(self, title: str, text: str, portal: str = "") -> None:
        self._close("modal")
        w = tk.Toplevel(self.root)
        w.title(title)
        w.attributes("-topmost", True)
        w.resizable(False, False)
        w.configure(bg=BG, padx=28, pady=22)
        tk.Label(w, text=title, bg=BG, fg=ACCENT, font=self.f_title).pack(anchor="w")
        tk.Label(w, text=text, bg=BG, fg=FG, font=self.f_text, wraplength=460, justify="left",
                 pady=12).pack(anchor="w")
        row = tk.Frame(w, bg=BG)
        row.pack(anchor="e", pady=(8, 0))
        if portal:
            tk.Button(row, text="Попросить ещё время", relief="flat", bg=BG, fg=ACCENT,
                      activebackground=BG, font=self.f_text, cursor="hand2",
                      command=lambda: self._open(portal + "/me")).pack(side="left", padx=6)
        tk.Button(row, text="Понятно", relief="flat", bg=ACCENT, fg=BG, font=self.f_text,
                  padx=16, command=lambda: self._close("modal")).pack(side="left")
        w.update_idletasks()
        sw, sh = w.winfo_screenwidth(), w.winfo_screenheight()
        w.geometry(f"+{(sw - w.winfo_width()) // 2}+{(sh - w.winfo_height()) // 3}")
        w.lift()
        w.focus_force()
        self.modal = w

    def _open(self, url: str) -> None:
        try:
            os.startfile(url)  # type: ignore[attr-defined]
        except OSError:
            pass
        self._close("modal")

    def set_lost(self, message: str | None) -> None:
        if not message:
            self._close("lost")
            return
        if self.lost is None:
            w = tk.Toplevel(self.root)
            w.overrideredirect(True)
            w.attributes("-topmost", True)
            w.configure(bg="#7a1c16")
            w.geometry(f"{w.winfo_screenwidth()}x{w.winfo_screenheight()}+0+0")
            w.protocol("WM_DELETE_WINDOW", lambda: None)
            self.lost_label = tk.Label(w, text="", bg="#7a1c16", fg="white", font=self.f_big,
                                       wraplength=int(w.winfo_screenwidth() * 0.7), justify="center")
            self.lost_label.place(relx=0.5, rely=0.45, anchor="center")
            self.lost = w
        self.lost_label.configure(text=message)
        self.lost.lift()
        self.lost.attributes("-topmost", True)
