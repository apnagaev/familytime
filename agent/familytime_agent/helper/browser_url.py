"""Адрес активной вкладки Chrome / Edge / Яндекс Браузера через UI Automation.

Берётся первое поле ввода в окне браузера, значение которого похоже на адрес (это адресная
строка). Чтение идёт в отдельном потоке и кешируется по (окно, заголовок): заголовок меняется
при смене вкладки или страницы.
"""
from __future__ import annotations

import logging
import queue
import re
import threading
import time

log = logging.getLogger("familytime.url")

_URLISH = re.compile(r"^(?:[a-z][a-z0-9+.\-]*://)?[^\s/]+\.[^\s/]{2,}(?:[/:?#].*)?$", re.I)


class UrlReader:
    def __init__(self):
        self.cache: dict[tuple[int, str], tuple[float, str]] = {}
        self.q: queue.Queue = queue.Queue(maxsize=4)
        self.lock = threading.Lock()
        threading.Thread(target=self._worker, name="uia", daemon=True).start()

    def get(self, hwnd: int, title: str) -> str:
        key = (hwnd, title)
        with self.lock:
            v = self.cache.get(key)
        if v and time.monotonic() - v[0] < 20:
            return v[1]
        try:
            self.q.put_nowait(key)
        except queue.Full:
            pass
        return v[1] if v else self.last_for(hwnd)

    def last_for(self, hwnd: int) -> str:
        with self.lock:
            best = [(t, u) for (h, _), (t, u) in self.cache.items() if h == hwnd]
        return max(best)[1] if best else ""

    def _worker(self) -> None:
        try:
            import uiautomation as auto
        except Exception as e:  # noqa: BLE001
            log.warning("UI Automation недоступна: %r", e)
            return
        log.info("UI Automation загружена")
        last_warn = 0.0
        ok_logged = False
        with auto.UIAutomationInitializerInThread():
            while True:
                key = self.q.get()
                url, diag = "", {}
                try:
                    url, diag = self._read(auto, key[0])
                except Exception as e:  # noqa: BLE001
                    diag = {"ошибка": repr(e)}
                if url and not ok_logged:
                    ok_logged = True
                    log.info("адрес вкладки читается")
                elif not url and time.monotonic() - last_warn > 60:
                    last_warn = time.monotonic()
                    log.warning("адрес вкладки не прочитан: %s", diag)
                with self.lock:
                    self.cache[key] = (time.monotonic(), url)
                    if len(self.cache) > 200:
                        for k in sorted(self.cache, key=lambda k: self.cache[k][0])[:100]:
                            del self.cache[k]

    @staticmethod
    def _read(auto, hwnd: int) -> tuple[str, dict]:
        """Ищет поле ввода с адресом. Возвращает (адрес, сведения для журнала, если не нашёл).

        В журнал попадают только названия полей и типы ошибок, не их содержимое.
        """
        win = auto.ControlFromHandle(hwnd)
        if not win:
            return "", {"окно": "не найдено"}
        found: list[str] = []
        diag = {"узлов": 0, "полей": [], "ошибки": []}

        def visit(ctrl, depth):
            if found or depth > 16:
                return
            diag["узлов"] += 1
            try:
                kind = ctrl.ControlTypeName
                if kind == "DocumentControl":
                    return                      # содержимое страницы не обходим
                if kind == "EditControl":
                    name = (ctrl.Name or "")[:40]
                    try:
                        val = (ctrl.GetValuePattern().Value or "").strip()
                    except Exception as e:  # noqa: BLE001
                        val = ""
                        diag["ошибки"].append(f"{name}: {type(e).__name__}")
                    if _URLISH.match(val):
                        found.append(val)
                        return
                    diag["полей"].append(f"{name} ({'пусто' if not val else 'не адрес'})")
                children = ctrl.GetChildren()
            except Exception as e:  # noqa: BLE001
                if len(diag["ошибки"]) < 3:
                    diag["ошибки"].append(type(e).__name__)
                return
            for child in children:
                visit(child, depth + 1)
                if found:
                    return

        visit(win, 0)
        if found:
            return found[0], {}
        diag["полей"] = diag["полей"][:5]
        diag["ошибки"] = diag["ошибки"][:5]
        return "", diag
