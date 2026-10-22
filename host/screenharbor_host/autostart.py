"""Start the host automatically at login (for unattended access).

Windows: HKCU Run key   Linux: XDG autostart .desktop   macOS: LaunchAgent plist
All per-user; no admin rights needed. The host needs a logged-in desktop session
to capture the screen, so "at login" (not "at boot") is the right trigger.
"""
from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

NAME = "ScreenHarbor"


def _command(args: list[str]) -> list[str]:
    exe = Path(sys.executable)
    if sys.platform == "win32" and "--headless" not in args:
        pythonw = exe.with_name("pythonw.exe")  # no console window for the GUI
        if pythonw.exists():
            exe = pythonw
    return [str(exe), "-m", "screenharbor_host", *args]


def install(args: list[str]) -> str:
    cmd = _command(args)
    if sys.platform == "win32":
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                            0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(cmd))
        return r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ScreenHarbor"
    if sys.platform == "darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "org.screenharbor.host.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            plistlib.dump({"Label": "org.screenharbor.host", "ProgramArguments": cmd, "RunAtLoad": True,
                           "KeepAlive": True, "ProcessType": "Interactive"}, f)
        subprocess.run(["launchctl", "load", "-w", str(path)], check=False)
        return str(path)
    path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "autostart" / "screenharbor.desktop"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[Desktop Entry]\nType=Application\nName=ScreenHarbor\nComment=ScreenHarbor remote desktop host\n"
                    f"Exec={shlex.join(cmd)}\nX-GNOME-Autostart-enabled=true\nTerminal=false\n", "utf-8")
    return str(path)


def uninstall() -> str:
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, NAME)
        except FileNotFoundError:
            pass
        return "registry Run key"
    if sys.platform == "darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "org.screenharbor.host.plist"
        if path.exists():
            subprocess.run(["launchctl", "unload", "-w", str(path)], check=False)
            path.unlink()
        return str(path)
    path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "autostart" / "screenharbor.desktop"
    path.unlink(missing_ok=True)
    return str(path)
