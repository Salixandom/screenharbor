"""Mouse/keyboard injection (pynput: SendInput on Windows, Quartz on macOS, XTest on X11)."""
from __future__ import annotations

from pynput.keyboard import Controller as KeyboardController, Key, KeyCode
from pynput.mouse import Button, Controller as MouseController

BUTTONS = {0: Button.left, 1: Button.middle, 2: Button.right}

# Keys identified by KeyboardEvent.code (location-sensitive keys).
BY_CODE = {
    "ShiftLeft": Key.shift_l, "ShiftRight": Key.shift_r,
    "ControlLeft": Key.ctrl_l, "ControlRight": Key.ctrl_r,
    "AltLeft": Key.alt_l, "AltRight": Key.alt_r,
    "MetaLeft": Key.cmd_l, "MetaRight": Key.cmd_r, "OSLeft": Key.cmd_l, "OSRight": Key.cmd_r,
    "Space": Key.space,
}

# Keys identified by KeyboardEvent.key.
BY_KEY = {
    "Enter": Key.enter, "Backspace": Key.backspace, "Tab": Key.tab, "Escape": Key.esc,
    "ArrowUp": Key.up, "ArrowDown": Key.down, "ArrowLeft": Key.left, "ArrowRight": Key.right,
    "Home": Key.home, "End": Key.end, "PageUp": Key.page_up, "PageDown": Key.page_down,
    "Delete": Key.delete, "CapsLock": Key.caps_lock,
    "Shift": Key.shift, "Control": Key.ctrl, "Alt": Key.alt, "Meta": Key.cmd,
}
for _i in range(1, 21):
    _k = getattr(Key, f"f{_i}", None)
    if _k is not None:
        BY_KEY[f"F{_i}"] = _k
for _name, _attr in (("Insert", "insert"), ("PrintScreen", "print_screen"), ("ContextMenu", "menu"),
                     ("NumLock", "num_lock"), ("ScrollLock", "scroll_lock"), ("Pause", "pause"),
                     ("AudioVolumeUp", "media_volume_up"), ("AudioVolumeDown", "media_volume_down"),
                     ("AudioVolumeMute", "media_volume_mute")):
    _k = getattr(Key, _attr, None)
    if _k is not None:
        BY_KEY[_name] = _k


def _clamp01(v) -> float:
    try:
        v = float(v)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if v != v else min(max(v, 0.0), 0.9999)


class InputController:
    def __init__(self) -> None:
        self._mouse = MouseController()
        self._kbd = KeyboardController()
        self._keys: dict[str, object] = {}  # code -> pressed pynput key
        self._buttons: set = set()

    def position(self) -> tuple[int, int]:
        return self._mouse.position

    def move(self, geo: dict, x, y) -> None:
        self._mouse.position = (int(geo["x"] + _clamp01(x) * geo["w"]), int(geo["y"] + _clamp01(y) * geo["h"]))

    def button(self, geo: dict, down: bool, b, x, y) -> None:
        btn = BUTTONS.get(b)
        if btn is None:
            return
        self.move(geo, x, y)
        if down:
            self._mouse.press(btn)
            self._buttons.add(btn)
        else:
            self._mouse.release(btn)
            self._buttons.discard(btn)

    def wheel(self, dx, dy) -> None:
        dx, dy = int(max(-20, min(20, dx or 0))), int(max(-20, min(20, dy or 0)))
        if dx or dy:
            self._mouse.scroll(dx, dy)

    @staticmethod
    def _resolve(code: str, key: str):
        if code in BY_CODE:
            return BY_CODE[code]
        if key in BY_KEY:
            return BY_KEY[key]
        if isinstance(key, str) and len(key) == 1:
            return KeyCode.from_char(key)
        return None

    def key(self, down: bool, code, key) -> None:
        code, key = str(code or ""), str(key or "")
        if down:
            k = self._keys.get(code) or self._resolve(code, key)
            if k is None:
                return
            self._keys[code] = k
            self._kbd.press(k)
        else:
            k = self._keys.pop(code, None) or self._resolve(code, key)
            if k is not None:
                self._kbd.release(k)

    def type_text(self, text: str) -> None:
        self._kbd.type(text[:10000])

    def release_keys(self) -> None:
        for k in list(self._keys.values()):
            try:
                self._kbd.release(k)
            except Exception:
                pass
        self._keys.clear()

    def release_all(self) -> None:
        self.release_keys()
        for b in list(self._buttons):
            try:
                self._mouse.release(b)
            except Exception:
                pass
        self._buttons.clear()
