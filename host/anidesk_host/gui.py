"""Tk host window: shows ID + password, asks to accept connections, lists sessions, chat."""
from __future__ import annotations

import asyncio
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from .agent import Agent
from .config import Config, generate_password

ACCENT = "#e8473f"


def fmt_id(i: str) -> str:
    return " ".join(i[k:k + 3] for k in range(0, len(i), 3)) if i else "—"


class TkUI:
    """Thread-safe bridge: agent (asyncio thread) -> Tk (main thread)."""

    def __init__(self) -> None:
        self.q: queue.Queue = queue.Queue()

    def status(self, text): self.q.put(("status", text))
    def id_changed(self, i): self.q.put(("id", i))
    def log(self, text): self.q.put(("log", text))
    def chat(self, session, text): self.q.put(("chat", session, text))
    def session_started(self, s): self.q.put(("sessions",))
    def session_ended(self, s): self.q.put(("sessions",))
    def sharing(self, url, code): self.q.put(("sharing", url, code))

    async def ask(self, session) -> bool:
        fut = asyncio.get_running_loop().create_future()
        self.q.put(("ask", session, fut))
        return await fut


class HostWindow:
    def __init__(self, cfg: Config, password: str | None, share: bool = False) -> None:
        self.cfg = cfg
        self.ui = TkUI()
        self.agent = Agent(cfg, self.ui, password)
        self.loop = asyncio.new_event_loop()
        self.root = tk.Tk()
        self.root.title("AniDesk")
        self.root.minsize(480, 680)
        self._build()
        threading.Thread(target=self._run_loop, daemon=True).start()
        self.root.after(100, self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self._quit)
        if share:
            self.root.after(300, self._toggle_share)

    # ------------------------------------------------------------ layout
    def _build(self) -> None:
        r = self.root
        style = ttk.Style(r)
        style.configure("Big.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Head.TLabel", font=("Segoe UI", 10, "bold"), foreground=ACCENT)

        top = ttk.Frame(r, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="This desk", style="Head.TLabel").grid(row=0, column=0, sticky="w")
        self.id_var = tk.StringVar(value=fmt_id(self.cfg.id))
        ttk.Label(top, textvariable=self.id_var, style="Big.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Button(top, text="Copy", command=lambda: self._clip(self.cfg.id)).grid(row=1, column=1, padx=4)

        ttk.Label(top, text="Session password").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.pw_var = tk.StringVar(value=self.agent.session_password)
        ttk.Label(top, textvariable=self.pw_var, font=("Consolas", 14)).grid(row=3, column=0, sticky="w")
        ttk.Button(top, text="Copy", command=lambda: self._clip(self.pw_var.get())).grid(row=3, column=1, padx=4)
        ttk.Button(top, text="New", command=self._new_password).grid(row=3, column=2)
        self.perm_btn = ttk.Button(top, command=self._set_permanent)
        self.perm_btn.grid(row=4, column=0, sticky="w", pady=(6, 0))
        self._refresh_perm_btn()

        srv = ttk.Frame(r, padding=(12, 0))
        srv.pack(fill="x")
        ttk.Label(srv, text="Server").pack(side="left")
        self.server_var = tk.StringVar(value=self.cfg.server)
        ttk.Entry(srv, textvariable=self.server_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(srv, text="Apply", command=self._apply_server).pack(side="left")

        share = ttk.LabelFrame(r, text="No server? Share via internet link", padding=8)
        share.pack(fill="x", padx=12, pady=(8, 0))
        self.share_btn = ttk.Button(share, text="Share via internet link", command=self._toggle_share)
        self.share_btn.grid(row=0, column=0, sticky="w")
        self.link_var = tk.StringVar()
        self.code_var = tk.StringVar()
        self.link_entry = ttk.Entry(share, textvariable=self.link_var, state="readonly", width=46)
        self.copy_link_btn = ttk.Button(share, text="Copy link", command=lambda: self._clip(self.link_var.get()))
        self.code_label = ttk.Label(share, textvariable=self.code_var, foreground="#666")

        self.status_var = tk.StringVar(value="Starting...")
        ttk.Label(r, textvariable=self.status_var, padding=(12, 4), foreground="#666").pack(fill="x")

        opts = ttk.LabelFrame(r, text="Permissions", padding=8)
        opts.pack(fill="x", padx=12, pady=4)
        self.vars = {}
        for i, (key, label) in enumerate((("ask", "Ask before accepting (session password)"),
                                          ("allow_input", "Allow mouse & keyboard control"),
                                          ("allow_files", "Allow file transfer"),
                                          ("allow_clipboard", "Allow clipboard sync"))):
            v = tk.BooleanVar(value=getattr(self.cfg, key))
            self.vars[key] = v
            ttk.Checkbutton(opts, text=label, variable=v, command=self._save_opts).grid(row=i, column=0, sticky="w")

        sess = ttk.LabelFrame(r, text="Active sessions", padding=8)
        sess.pack(fill="x", padx=12, pady=4)
        self.sess_list = tk.Listbox(sess, height=3)
        self.sess_list.pack(side="left", fill="x", expand=True)
        ttk.Button(sess, text="Disconnect", command=self._disconnect).pack(side="left", padx=6)

        chat = ttk.LabelFrame(r, text="Chat & log", padding=8)
        chat.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        self.log_box = tk.Text(chat, height=8, state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True)
        row = ttk.Frame(chat)
        row.pack(fill="x", pady=(6, 0))
        self.chat_var = tk.StringVar()
        e = ttk.Entry(row, textvariable=self.chat_var)
        e.pack(side="left", fill="x", expand=True)
        e.bind("<Return>", lambda _e: self._send_chat())
        ttk.Button(row, text="Send", command=self._send_chat).pack(side="left", padx=(6, 0))

    # ----------------------------------------------------------- actions
    def _clip(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _new_password(self) -> None:
        pw = generate_password()
        self.agent.set_session_password(pw)
        self.pw_var.set(pw)

    def _refresh_perm_btn(self) -> None:
        on = bool(self.cfg.pw_key)
        self.perm_btn.config(text="Unattended password: ON (change / remove)" if on else "Set unattended password...")

    def _set_permanent(self) -> None:
        pw = simpledialog.askstring(
            "Unattended access",
            "Password for connecting without confirmation.\nLeave empty to disable unattended access.",
            show="*", parent=self.root)
        if pw is None:
            return
        if pw and len(pw) < 8:
            messagebox.showwarning("AniDesk", "Use at least 8 characters.", parent=self.root)
            return
        self.agent.set_permanent_password(pw)
        self._refresh_perm_btn()

    def _toggle_share(self) -> None:
        self.share_btn.config(state="disabled")
        if self.agent.relay is not None:
            fut = asyncio.run_coroutine_threadsafe(self.agent.stop_sharing(), self.loop)
            fut.add_done_callback(lambda f: self.ui.q.put(("sharing", None, None)))
            return

        async def start():
            url = await self.agent.start_sharing()
            while self.agent.relay is not None and self.agent.relay.host_id != self.agent.ident[0]:
                await asyncio.sleep(0.1)
            return url

        def done(f):
            try:
                url = f.result()
                self.ui.q.put(("sharing", f"{url}/#id={self.agent.ident[0]}", self.agent.tunnel.code))
            except Exception as e:
                self.ui.q.put(("sharing_err", str(e)))

        asyncio.run_coroutine_threadsafe(start(), self.loop).add_done_callback(done)

    def _show_share(self, link, code) -> None:
        self.share_btn.config(state="normal", text="Stop sharing" if link else "Share via internet link")
        if link:
            self.link_var.set(link)
            self.code_var.set(f"Code: {code}   - send the link (or code) and the password")
            self.link_entry.grid(row=1, column=0, sticky="we", pady=(6, 0))
            self.copy_link_btn.grid(row=1, column=1, padx=4, pady=(6, 0))
            self.code_label.grid(row=2, column=0, columnspan=2, sticky="w")
            self._log(f"Sharing link ready: {link}")
        else:
            for w in (self.link_entry, self.copy_link_btn, self.code_label):
                w.grid_remove()
            self._log("Stopped sharing via link")

    def _apply_server(self) -> None:
        url = self.server_var.get().strip()
        if url != self.cfg.server:
            self.cfg.server = url
            self.cfg.id = self.cfg.secret = ""  # IDs are per server
            self.cfg.save()
            self.id_var.set(fmt_id(""))
        self.loop.call_soon_threadsafe(self.agent.reconnect)

    def _save_opts(self) -> None:
        for k, v in self.vars.items():
            setattr(self.cfg, k, v.get())
        self.cfg.save()

    def _sessions(self) -> list:
        return sorted(self.agent.sessions, key=lambda s: s.started)

    def _disconnect(self) -> None:
        sel = self.sess_list.curselection()
        sessions = [s for s in self._sessions() if s.ch is not None]
        targets = [sessions[i] for i in sel if i < len(sessions)] or sessions
        for s in targets:
            asyncio.run_coroutine_threadsafe(s.close(), self.loop)

    def _send_chat(self) -> None:
        text = self.chat_var.get().strip()
        if not text:
            return
        self.chat_var.set("")
        for s in self._sessions():
            if s.ch is not None:
                asyncio.run_coroutine_threadsafe(s.chat(text), self.loop)
        self._log(f"You: {text}")

    def _log(self, text: str) -> None:
        self.log_box.config(state="normal")
        self.log_box.insert("end", time.strftime("%H:%M ") + text + "\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _ask(self, session, fut) -> None:
        win = tk.Toplevel(self.root)
        win.title("Incoming connection")
        win.attributes("-topmost", True)
        win.resizable(False, False)
        ttk.Label(win, text=f"{session.viewer_name} wants to control this computer",
                  font=("Segoe UI", 11, "bold"), padding=(16, 16, 16, 4)).pack()
        ttk.Label(win, text=f"From {session.ip}. Only accept if you know who this is.",
                  padding=(16, 0, 16, 12)).pack()
        btns = ttk.Frame(win, padding=12)
        btns.pack()

        def done(ok: bool) -> None:
            win.destroy()
            self.loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result(ok))
            self._log(("Accepted " if ok else "Declined ") + session.label)

        ttk.Button(btns, text="Accept", command=lambda: done(True)).pack(side="left", padx=6)
        ttk.Button(btns, text="Decline", command=lambda: done(False)).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", lambda: done(False))
        win.after(59000, lambda: win.winfo_exists() and done(False))
        self.root.bell()
        self.root.deiconify()
        win.lift()
        win.focus_force()

    # -------------------------------------------------------------- loop
    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.agent.run())

    def _poll(self) -> None:
        try:
            while True:
                ev = self.ui.q.get_nowait()
                kind = ev[0]
                if kind == "status":
                    self.status_var.set(ev[1])
                elif kind == "id":
                    self.id_var.set(fmt_id(ev[1]))
                elif kind == "log":
                    self._log(ev[1])
                elif kind == "chat":
                    self._log(f"{ev[1].viewer_name}: {ev[2]}")
                    self.root.bell()
                elif kind == "ask":
                    self._ask(ev[1], ev[2])
                elif kind == "sharing":
                    self._show_share(ev[1], ev[2])
                elif kind == "sharing_err":
                    self.share_btn.config(state="normal", text="Share via internet link")
                    self._log(f"Could not share: {ev[1]}")
                    messagebox.showerror("AniDesk", "Could not open the sharing link:\n" + ev[1], parent=self.root)
                elif kind == "sessions":
                    self.sess_list.delete(0, "end")
                    for s in self._sessions():
                        if s.ch is not None:
                            self.sess_list.insert("end", "● " + s.label)
                    self.root.title("AniDesk - REMOTE SESSION ACTIVE" if self.sess_list.size() else "AniDesk")
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _quit(self) -> None:
        fut = asyncio.run_coroutine_threadsafe(self.agent.stop(), self.loop)
        try:
            fut.result(timeout=2)
        except Exception:
            pass
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
