# -*- mode: python ; coding: utf-8 -*-
# Сборка: pyinstaller familytime.spec  →  dist\FamilyTime\ (служба и помощник в одной папке)
from PyInstaller.utils.hooks import collect_all

# Обёртки comtypes для UI Automation генерирует build.ps1 до сборки (в .venv), здесь они
# попадают в exe. Без них помощник генерирует их на лету в каждом обращении и не читает адрес.
datas, binaries, hidden = [], [], [
    "comtypes.gen.UIAutomationClient", "comtypes.gen.stdole",
    "comtypes.gen._944DE083_8FB8_45CF_BCB7_C477ACB2F897_0_1_0",
    "comtypes.gen._00020430_0000_0000_C000_000000000046_0_2_0",
]
for pkg in ("uiautomation", "comtypes"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hidden += h

a_agent = Analysis(["run_agent.py"], hiddenimports=["win32timezone", "servicemanager"],
                   excludes=["tkinter"])
a_helper = Analysis(["run_helper.py"], datas=datas, binaries=binaries,
                    hiddenimports=hidden + ["win32timezone", "win32api", "win32com.shell.shell",
                                            "win32com.shell.shellcon"])

pyz_agent = PYZ(a_agent.pure)
pyz_helper = PYZ(a_helper.pure)

exe_agent = EXE(pyz_agent, a_agent.scripts, [], exclude_binaries=True, name="familytime-agent",
                console=True, version="version_info.txt")
exe_helper = EXE(pyz_helper, a_helper.scripts, [], exclude_binaries=True, name="familytime-helper",
                 console=False, version="version_info.txt")

coll = COLLECT(exe_agent, a_agent.binaries, a_agent.datas,
               exe_helper, a_helper.binaries, a_helper.datas,
               name="FamilyTime")
