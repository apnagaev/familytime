"""Служба Windows FamilyTime (от SYSTEM).

familytime-agent.exe              — запуск диспетчером служб
familytime-agent.exe console      — тот же цикл в консоли (отладка, от администратора)
familytime-agent.exe install|remove|start|stop — стандартные команды pywin32
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import time

import servicemanager
import win32event
import win32service
import win32serviceutil

from .. import VERSION
from ..core.engine import TICK, Engine
from ..core.state import Store, load_config

DATA_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "FamilyTime")


def install_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def setup_logging(console: bool = False) -> None:
    os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
    h = logging.handlers.RotatingFileHandler(os.path.join(DATA_DIR, "logs", "agent.log"),
                                             maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handlers: list[logging.Handler] = [h]
    if console:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def run_loop(should_stop) -> None:
    from .platform import WinPlatform
    log = logging.getLogger("familytime")
    cfg = load_config(os.path.join(DATA_DIR, "config.json"))
    eng = Engine(cfg, Store(os.path.join(DATA_DIR, "state.json")), WinPlatform(install_dir()))
    log.info("FamilyTime %s запущен, сервер %s", VERSION, cfg["server_url"])
    while not should_stop(TICK):
        try:
            eng.step()
        except Exception:  # noqa: BLE001 — служба не должна падать из-за одного шага
            log.exception("ошибка шага")
    eng.save()
    log.info("остановлен")


class FamilyTimeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "FamilyTime"
    _svc_display_name_ = "FamilyTime"
    _svc_description_ = "Учёт и ограничение времени за компьютером, локация компьютера."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        setup_logging()
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))

        def should_stop(timeout):
            return win32event.WaitForSingleObject(self.stop_event, int(timeout * 1000)) \
                == win32event.WAIT_OBJECT_0
        run_loop(should_stop)


def main() -> None:
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FamilyTimeService)
        servicemanager.StartServiceCtrlDispatcher()
    elif sys.argv[1] == "console":
        setup_logging(console=True)
        try:
            run_loop(lambda t: time.sleep(t) or False)
        except KeyboardInterrupt:
            pass
    elif sys.argv[1] == "--version":
        print(VERSION)
    else:
        win32serviceutil.HandleCommandLine(FamilyTimeService)


if __name__ == "__main__":
    main()
