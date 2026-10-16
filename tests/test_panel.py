#!/usr/bin/env python3
"""test_panel.py — панель Mini App в настоящем браузере (Chromium через Playwright).

Поднимает panel_stand.py (сервер панели на песочнице awg2) с профилями
сервера lite и pro и без сервера и гоняет panel_drive.js: клиенты, сервер,
туннели, диагностика, бэкапы, обновление, мастер создания сервера, ошибки в
консоли, текст «null» на экранах. Нет node, Playwright или
Chromium — тест пропускается.

Запуск:  python3 tests/test_panel.py [путь/к/dist/awg2.sh]
         (python с aiogram; AWG_PANEL_SHOTS=каталог — оставить скриншоты)
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
fails = checks = 0


def chk(label, cond, detail=""):
    global fails, checks
    checks += 1
    if cond:
        print(f"  OK   {label}")
    else:
        fails += 1
        print(f"  FAIL {label}" + (f"\n       {detail}" if detail else ""))


def skip(why):
    print(f"Панель в браузере пропущена: {why}")
    sys.exit(0)


node = shutil.which("node") or skip("нет node")
npm = shutil.which("npm") or skip("нет npm")
env = dict(os.environ)
env["NODE_PATH"] = subprocess.run([npm, "root", "-g"], capture_output=True, text=True).stdout.strip()
if subprocess.run([node, "-e", "require('playwright')"], env=env, capture_output=True).returncode:
    skip("нет Playwright для node (npm i -g playwright)")
try:
    import aiogram  # noqa: F401
except ImportError:
    skip("нет aiogram (pip install -r awg_bot/requirements.txt)")
if len(sys.argv) > 1:
    env["AWG2_SH"] = os.path.abspath(sys.argv[1])

keep = os.environ.get("AWG_PANEL_SHOTS")
THEMES = {"lite": "light", "pro": "dark", "none": "light"}      # обе темы Telegram
for profile in ("lite", "pro", "none"):
    print(f"Профиль сервера: {profile}, тема {THEMES[profile]}")
    out = os.path.join(keep, profile) if keep else tempfile.mkdtemp(prefix="panel-shots.")
    os.makedirs(out, exist_ok=True)
    stand = subprocess.Popen([sys.executable, os.path.join(HERE, "panel_stand.py")], env=dict(env, PROFILE=profile),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        ready = ""
        for line in stand.stdout:
            if line.startswith("READY"):
                ready = line.split()
                break
        if not ready:
            chk("стенд панели поднялся", False, stand.stdout.read()[-800:] if stand.stdout else "")
            continue
        _, port, init, err, root = ready[:5]
        chk("стенд панели поднялся", err == "-", err)
        try:
            run = subprocess.run([node, os.path.join(HERE, "panel_drive.js"), port, init, out, THEMES[profile], profile, root],
                                 env=env, capture_output=True, text=True, timeout=900)
            output = run.stdout + run.stderr
        except subprocess.TimeoutExpired:
            output = "сценарий не уложился в 900 с"
        log = os.path.join(out, "run.log")
        lines = open(log).read().splitlines() if os.path.exists(log) else []
        chk("сценарий браузера отработал", bool(lines), output[-800:])
        for line in lines:
            if line.startswith(("OK", "FAIL")):
                status, _, rest = line.partition(" ")
                chk(rest.strip(), status == "OK", rest)
            elif line.startswith("ALERTS"):
                chk("без неожиданных окон с ошибкой", line.strip() == "ALERTS []", line[:600])
            elif line.startswith("ERRORS"):
                chk("без ошибок в консоли страницы", line.strip() == "ERRORS []", line[:600])
    finally:
        stand.terminate()
        stand.wait(timeout=20)
        if not keep:
            shutil.rmtree(out, ignore_errors=True)

print(f"\nпроверок: {checks}, провалов: {fails}")
sys.exit(1 if fails else 0)
