#!/usr/bin/env python3
"""test_web.py — веб-панель (awgbot.web): вход и защита на настоящем сервере.

Поднимает web_stand.py (сервер панели на песочнице awg2, самоподписанный
сертификат) и проверяет по HTTPS: секретный путь, вход и блокировку перебора,
cookie сессии, CSRF, заголовки, скачивание файлов, смену пароля, выход.
Затем — тот же вход в Chromium (если есть Playwright для node).

Запуск:  python3 tests/test_web.py [путь/к/dist/awg2.sh]   (python с aiogram)
"""
import http.cookiejar
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

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


try:
    import aiogram  # noqa: F401
    import aiohttp  # noqa: F401
except ImportError:
    print("Веб-панель пропущена: нет aiogram/aiohttp (pip install -r awg_bot/requirements.txt)")
    sys.exit(0)

env = dict(os.environ, PROFILE="pro")
if len(sys.argv) > 1:
    env["AWG2_SH"] = os.path.abspath(sys.argv[1])
stand = subprocess.Popen([sys.executable, os.path.join(HERE, "web_stand.py")], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
ready = ""
for _ in range(240):
    line = stand.stdout.readline()
    if line.startswith("READY"):
        ready = line
        break
    if not line and stand.poll() is not None:
        break
if not ready:
    print("стенд не поднялся:", stand.stdout.read()[-2000:])
    sys.exit(1)
_, PORT, BASE, USER, PASSWORD, ROOT = ready.split()
HOST = f"https://127.0.0.1:{PORT}"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                              urllib.request.HTTPCookieProcessor(self.jar))
        self.op.addheaders = []

    def req(self, path, body=None, headers=None, method=None, raw=False):
        data = json.dumps(body).encode() if body is not None and not raw else body
        h = {"Content-Type": "application/json"} if body is not None and not raw else {}
        h.update(headers or {})
        r = urllib.request.Request(HOST + path, data=data, headers=h, method=method or ("POST" if data is not None else "GET"))
        try:
            with self.op.open(r, timeout=60) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def api(self, path, body=None, **kw):
        st, hd, data = self.req(BASE + path.lstrip("/"), {} if body is None else body, **kw)
        try:
            return st, json.loads(data)
        except ValueError:
            return st, {"raw": data[:200]}

    def login(self, user=USER, password=PASSWORD):
        return self.api("api/login", {"user": user, "password": password})


try:
    print("Секретный путь и страница")
    c = Client()
    st = [c.req(p)[0] for p in ("/", "/wrong/", "/api/me", "/app.js", BASE + "../web.py", BASE + "app.js/..%2f..%2fweb.py")]
    chk("всё, кроме секретного пути, — 404 (сканер не видит даже вход)", st[:4] == [404, 404, 404, 404] and 200 not in st, st)
    st, hd, page = c.req(BASE)
    chk("по секретному пути — страница без скрипта Telegram, с web.js",
        st == 200 and b"telegram.org" not in page and b'src="web.js"' in page, page[:300])
    chk("заголовки: CSP только своё, без фреймов, без referrer, Server скрыт",
        "script-src 'self'" in hd.get("Content-Security-Policy", "") and hd.get("X-Frame-Options") == "DENY"
        and hd.get("Referrer-Policy") == "no-referrer" and hd.get("Server") == "awg"
        and hd.get("X-Content-Type-Options") == "nosniff", hd)
    st, _, js = c.req(BASE + "web.js")
    chk("web.js: базовый путь для запросов", st == 200 and BASE.encode() in js, js)
    st, hd, font = c.req(BASE + "fonts/plex-sans-cyrillic-400.woff2")
    chk("шрифт «Карточек»: woff2, кэш на неделю, без входа (страница входа — тем же шрифтом)",
        st == 200 and font[:4] == b"wOF2" and hd.get("Content-Type") == "font/woff2"
        and hd.get("Cache-Control") == "public, max-age=604800" and "script-src 'self'" in hd.get("Content-Security-Policy", ""),
        [st, hd.get("Content-Type"), hd.get("Cache-Control")])
    st = [c.req(BASE + p)[0] for p in ("fonts/nope.woff2", "fonts/OFL.txt", "fonts/..%2fapp.js", "fonts/plex-sans-latin-400.woff")]
    chk("шрифты: только существующие .woff2 из каталога шрифтов", st == [404, 404, 404, 404], st)
    chk("остальное по-прежнему без кэша", c.req(BASE + "web.js")[1].get("Cache-Control") == "no-store")

    print("Без входа")
    for path in ("api/me", "api/status", "api/call", "api/clients", "api/download", "api/web/account", "api/backup/upload"):
        st, d = c.api(path, {"args": ["status"]})
        if st != 401:
            break
    chk("API без входа — 401 и признак «нужен вход»", st == 401 and d.get("login") is True, [path, st, d])

    print("Вход")
    st, d = c.login(password="wrong-password")
    chk("неверный пароль — 401, текст без подсказки, что неверно", st == 401 and d.get("error") == "Неверный логин или пароль", d)
    st, d = c.login(user="root", password=PASSWORD)
    chk("неверный логин — тот же ответ", st == 401 and d.get("error") == "Неверный логин или пароль", d)
    t = time.time()
    st, hd, _ = c.req(BASE + "api/login", {"user": USER, "password": PASSWORD})
    cookie = hd.get("Set-Cookie", "")
    chk("верный пароль — сессия в cookie: HttpOnly, Secure, SameSite=Strict, только на путь панели",
        st == 200 and "awg_web=" in cookie and "HttpOnly" in cookie and "Secure" in cookie
        and "SameSite=Strict" in cookie and f"Path={BASE}" in cookie, cookie)
    st, d = c.api("api/me")
    chk("после входа — API отвечает, пользователь — владелец", st == 200 and d.get("name") == USER and d.get("owner") is True, d)
    st, d = c.api("api/call", {"args": ["status"]})
    chk("вызов awg2 api через панель", st == 200 and d.get("ok") is True, d)
    conf = open(os.path.join(ROOT, "..", "web", "awg-web.conf")).read()
    chk("в конфиге — хеш scrypt, пароля нет", "WEB_PASS=scrypt$" in conf and PASSWORD not in conf, conf)

    print("Чужие сайты")
    for _ in range(5):
        c.api("api/nope", {}, headers={"Origin": "https://" + "a" * 8000})
    st, d = c.api("api/call", {"args": ["status"]}, headers={"Origin": "https://evil.example"})
    chk("запрос с чужого сайта (Origin) — 403", st == 403, d)
    csrf = [ln for ln in open(os.path.join(ROOT, "..", "web", "awg-web.log")).read().splitlines() if " CSRF " in ln]
    chk("запросы с чужих сайтов не раздувают журнал: одна строка за 10 с, Origin обрезан",
        len(csrf) == 1 and "aaaa" in csrf[0] and len(csrf[0]) < 160, csrf)
    st, d = c.api("api/call", {"args": ["status"]}, headers={"Sec-Fetch-Site": "cross-site"})
    chk("без Origin, но cross-site — 403", st == 403, d)
    st, d = c.api("api/call", {"args": ["status"]}, headers={"Origin": f"https://127.0.0.1:{PORT}"})
    chk("со своей страницы — проходит", st == 200, d)

    print("Файлы")
    st, hd, data = c.req(BASE + "api/download", {"what": "conf", "name": "alice"})
    chk("конфиг клиента — скачиванием, с именем файла",
        st == 200 and "attachment" in hd.get("Content-Disposition", "") and b"[Interface]" in data, [st, hd, data[:80]])
    chk("конфиг — не text/plain (иначе телефон сохранит «имя.conf.txt»)",
        hd.get("Content-Type", "").startswith("application/octet-stream")
        and re.search(r'filename="[^"]+\.conf"', hd.get("Content-Disposition", "")), hd)
    st, hd, data = c.req(BASE + "api/download", {"what": "conf_zip", "name": "alice"})
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        inside = {n: z.read(n) for n in z.namelist()}
    except zipfile.BadZipFile:
        inside = {}
    chk("ZIP с конфигом: «имя.zip», внутри один «имя.conf»",
        st == 200 and hd.get("Content-Type", "").startswith("application/zip")
        and re.search(r'filename="[^"]+\.zip"', hd.get("Content-Disposition", ""))
        and len(inside) == 1 and all(n.endswith(".conf") and b"[Interface]" in v for n, v in inside.items()),
        [st, hd, list(inside)])
    st, hd, data = c.req(BASE + "api/download", {"what": "backup", "path": "/etc/shadow"})
    chk("файл не из списка бэкапов — отказ (не чтение любого файла)", st == 400 and b"root:" not in data, [st, data[:120]])
    st, d = c.api("api/send", {"what": "conf", "name": "alice"})
    chk("«в чат» в веб-панели — понятный отказ, без падения", st == 409 and "Telegram-бот" in d.get("error", ""), [st, d])
    st, d = c.api("api/download", {"what": "conf", "name": "../../etc/passwd"})
    chk("имя клиента с путём — отказ", st == 400, [st, d])

    print("Доступ: по адресам и только через VPN")
    nets_file = os.path.join(ROOT, "..", "web", "access.nets")
    wconf = os.path.join(ROOT, "..", "web", "awg-web.conf")
    st, d = c.api("api/web/account")
    a = d.get("access") or {}
    chk("аккаунт: доступ «для всех», мой адрес, адрес панели изнутри VPN (адрес awg0)",
        st == 200 and a.get("mode") == "all" and a.get("me") == "127.0.0.1" and not a.get("me_vpn") and a.get("me_self")
        and re.match(r"https://10\.\d+\.\d+\.\d+:" + PORT + "/s3cr3tPath/$", a.get("vpn_url", "")), a)
    st, d = c.api("api/web/access", {"mode": "ip", "allow": ["300.1.1.1", "198.51.100.7"]})
    chk("неверный адрес — 400 с понятной ошибкой, режим не сменился",
        st == 400 and "300.1.1.1" in d.get("error", "") and "WEB_ACCESS=" not in open(wconf).read(), d)
    st, d = c.api("api/web/access", {"mode": "ip", "allow": []})
    chk("«по адресам» с пустым списком — отказ", st == 400 and d.get("error"), d)
    st, d = c.api("api/web/access", {"mode": "root", "allow": []})
    st2, d2 = c.api("api/web/access", {"mode": "ip", "allow": "198.51.100.7"})
    chk("неизвестный режим, список не списком — 400", st == 400 and st2 == 400, [d, d2])
    st, d = c.api("api/web/access", {"mode": "ip", "allow": ["198.51.100.7", "203.0.113.0/24", "2001:db8::/32"]})
    nets = open(nets_file).read().split() if os.path.exists(nets_file) else []
    st2, acc = c.api("api/web/account")
    a = acc.get("access") or {}
    chk("«по адресам»: принят; в списке панели — адреса и подсеть VPN; с самого сервера панель открывается",
        st == 200 and {"198.51.100.7/32", "203.0.113.0/24", "2001:db8::/32"} <= set(nets)
        and any(n.startswith("10.") for n in nets) and a.get("mode") == "ip"
        and a.get("allow") == ["198.51.100.7/32", "203.0.113.0/24", "2001:db8::/32"] and c.api("api/me")[0] == 200,
        [st, d, nets, a])
    st, d = c.api("api/web/access", {"mode": "vpn"})
    nets = open(nets_file).read().split() if os.path.exists(nets_file) else []
    conf_now = open(wconf).read()
    chk("«только через VPN»: в списке только подсеть VPN; список адресов сохранён для возврата",
        st == 200 and nets and all(n.startswith("10.") for n in nets) and "WEB_ACCESS=vpn" in conf_now
        and "WEB_ALLOW=198.51.100.7/32,203.0.113.0/24,2001:db8::/32" in conf_now and c.api("api/me")[0] == 200,
        [st, d, nets, conf_now])
    st, d = c.api("api/web/access", {"mode": "all"})
    chk("«для всех»: список панели убран", st == 200 and not os.path.exists(nets_file)
        and "WEB_ACCESS=all" in open(wconf).read(), [st, d])
    wlog = open(os.path.join(ROOT, "..", "web", "awg-web.log")).read()
    chk("смены доступа — в журнале", wlog.count(" ACCESS 127.0.0.1 ") == 3 and " ACCESS 127.0.0.1 ip 198.51.100.7" in wlog,
        wlog[-500:])

    # Проверка адреса самой панелью: чужой адрес — 404 до входа и до API
    code = r"""
import asyncio, ipaddress, json, os, sys
from unittest import mock
sys.path.insert(0, sys.argv[1])
from aiohttp import web as aw
from aiohttp.test_utils import make_mocked_request
from awgbot import web
d = sys.argv[2]
open(web.CONF, "w").write("WEB_PORT=1\nWEB_PATH=p\nWEB_ACCESS=ip\n")
out = {}
acc = web.Access()
out["no_file"] = [acc.allowed("198.51.100.7"), acc.allowed("127.0.0.1"), acc.allowed("::1")]
open(web.NETS_FILE, "w").write("198.51.100.0/24\n10.8.0.0/24\n2001:db8::/32\nмусор\n")
out["ip"] = [acc.allowed(x) for x in ("198.51.100.7", "::ffff:198.51.100.9", "10.8.0.5", "2001:db8::5",
                                      "203.0.113.1", "2001:db9::1", "", None, "fe80::1%eth0", "127.0.0.1")]
open(web.CONF, "w").write("WEB_PORT=1\nWEB_PATH=p\nWEB_ACCESS=all\n")
out["all"] = acc.allowed("203.0.113.1")
open(web.CONF, "w").write("WEB_PORT=1\nWEB_PATH=p\nWEB_ACCESS=vpn\n")
out["vpn"] = [acc.allowed("10.8.0.5"), acc.allowed("203.0.113.1")]

async def go(remote, local="203.0.113.50"):
    srv = web.WebPanel()
    tr = mock.Mock()
    tr.get_extra_info.side_effect = lambda k, default=None: ((remote, 1234) if k == "peername"
                                                             else (local, 443) if k == "sockname" else default)
    req = make_mocked_request("GET", "/p/", transport=tr)
    async def handler(r):
        return aw.Response(text="panel")
    try:
        r = await srv.guard_mw(req, handler)
        return r.status
    except aw.HTTPException as e:
        return e.status
out["mw"] = [asyncio.run(go("203.0.113.1")), asyncio.run(go("10.8.0.5")), asyncio.run(go("203.0.113.50")),
             asyncio.run(go("::ffff:203.0.113.50")), asyncio.run(go("2001:db9::7", "2001:db9::7"))]
print(json.dumps(out))
"""
    ud = os.path.join(ROOT, "..", "acc-unit")
    os.makedirs(ud, exist_ok=True)
    uenv = dict(os.environ, AWG_WEB_CONF=os.path.join(ud, "w.conf"), AWG_WEB_NETS=os.path.join(ud, "nets"),
                AWG_WEB_LOG=os.path.join(ud, "w.log"), AWG_WEB_DIR=os.path.join(ud, "self"),
                AWG_BOT_CONF=os.path.join(ud, "none.conf"))
    r = subprocess.run([sys.executable, "-c", code, os.path.join(HERE, "..", "awg_bot"), ud],
                       env=uenv, capture_output=True, text=True, timeout=120)
    try:
        u = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        u = {}
    chk("панель сама: режим ограничен, а списка нет — никого, кроме самого сервера",
        u.get("no_file") == [False, True, True], [u, r.stderr[-800:]])
    chk("панель сама: адреса и подсети из списка (и IPv4 в виде ::ffff:), чужие — нет; мусор в файле не мешает",
        u.get("ip") == [True, True, True, True, False, False, False, False, False, True], u)
    chk("панель сама: «для всех» — все; «через VPN» — только свой VPN", u.get("all") is True
        and u.get("vpn") == [True, False], u)
    chk("панель сама: чужой адрес — 404 до входа и API, свой — дальше", u.get("mw", [])[:2] == [404, 200], u)
    chk("панель сама: с адреса сервера на него же (прокси на сервере, 3x-ui и т. п.) — как чужой адрес, 404",
        u.get("mw", [])[2:] == [404, 404, 404], u)
    # Возврат правила: любой сбой одного круга (здесь — не-UTF-8 в stderr apply) не останавливает задачу
    fw = os.path.join(ud, "fw.sh")
    open(fw, "w").write("#!/bin/bash\necho \"$1\" >> \"$(dirname \"$0\")/fw.calls\"\n"
                        "[[ $1 == check ]] && exit 1\nprintf 'bad \\xff\\xfe\\n' >&2\nexit 1\n")
    os.chmod(fw, 0o755)
    try:
        os.remove(os.path.join(ud, "fw.calls"))
    except OSError:
        pass
    code2 = ("import asyncio, sys\nsys.path.insert(0, sys.argv[1])\nfrom awgbot import web\n"
             "web.FW_SCRIPT, web.FW_EVERY = sys.argv[2], 0.2\n"
             "async def go():\n    srv = web.WebPanel()\n    t = asyncio.create_task(srv.watch_fw())\n"
             "    await asyncio.sleep(2)\n    t.cancel()\n    print('alive' if not t.done() or t.cancelled() else 'dead')\n"
             "asyncio.run(go())\n")
    r = subprocess.run([sys.executable, "-c", code2, os.path.join(HERE, "..", "awg_bot"), fw],
                       env=uenv, capture_output=True, text=True, timeout=60)
    try:
        calls = open(os.path.join(ud, "fw.calls")).read().split()
    except OSError:
        calls = []
    chk("правило доступа: фоновая задача переживает сбой круга и проверяет дальше",
        r.stdout.strip().endswith("alive") and calls.count("apply") >= 2, [r.stdout[-200:], r.stderr[-300:], calls])
    print("Смена пароля и сессии")
    c2 = Client()
    c2.login()
    st, d = c.api("api/web/password", {"old": "wrong-password", "new": "Another-pass-77"})
    chk("смена пароля: неверный текущий — отказ", st == 403, d)
    st, d = c.api("api/web/password", {"old": PASSWORD, "new": "short"})
    chk("смена пароля: короткий новый — отказ", st == 400, d)
    st, d = c.api("api/web/password", {"old": PASSWORD, "new": "Another-pass-77"})
    chk("смена пароля — другие сессии завершены", st == 200 and d.get("dropped", 0) >= 1, d)
    chk("другая сессия после смены пароля — 401", c2.api("api/me")[0] == 401)
    chk("эта сессия жива", c.api("api/me")[0] == 200)
    chk("старый пароль больше не подходит", Client().login()[0] == 401)
    c3 = Client()
    chk("новый пароль подходит", c3.login(password="Another-pass-77")[0] == 200)
    st, d = c.api("api/web/account")
    chk("аккаунт: сессии и журнал входов", st == 200 and len(d.get("sessions", [])) >= 2
        and any(" LOGIN " in ln for ln in d.get("log", [])) and any(" PASSWD " in ln for ln in d.get("log", [])), d)
    st, d = c.api("api/web/sessions/drop")
    chk("«завершить остальные сессии»", st == 200 and d.get("dropped", 0) >= 1 and c3.api("api/me")[0] == 401, d)
    st, d = c.api("api/logout")
    chk("выход — сессия больше не действует", st == 200 and c.api("api/me")[0] == 401, d)

    print("Перебор")
    b = Client()
    # Разом и с медленным телом: заголовки — сразу, тела — потом все вместе.
    # Раньше все такие запросы проходили проверку блокировки, пока сервер ждал
    # тело, и до первого засчитанного неверного пароля
    import socket

    def slow_login(i):
        sk = CTX.wrap_socket(socket.create_connection(("127.0.0.1", int(PORT)), timeout=60), server_hostname="127.0.0.1")
        body = json.dumps({"user": USER, "password": f"guess-{i}"}).encode()
        sk.sendall((f"POST {BASE}api/login HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode())
        return sk, body

    conns = [slow_login(i) for i in range(12)]
    time.sleep(1)
    for sk, body in conns:
        sk.sendall(body)
    codes = []
    for sk, _ in conns:
        data = b""
        while chunk := sk.recv(65536):
            data += chunk
        sk.close()
        codes.append(int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0)
    codes.sort()
    st, d = b.login(password="Another-pass-77")
    chk("12 неверных паролей разом, тела после заголовков — проверено 5, остальные 429; адрес заблокирован, даже верный пароль не пускает",
        codes == [401] * 5 + [429] * 7 and st == 429 and "мин" in d.get("error", ""), [codes, st, d])
    log = open(os.path.join(ROOT, "..", "web", "awg-web.log")).read()
    chk("в журнале — неверные пароли и блокировка с адресом", log.count(" FAIL 127.0.0.1") >= 5 and " LOCK 127.0.0.1" in log, log[-400:])

    node, npm = shutil.which("node"), shutil.which("npm")
    nenv = dict(os.environ)
    if node and npm:
        nenv["NODE_PATH"] = subprocess.run([npm, "root", "-g"], capture_output=True, text=True).stdout.strip()
    if node and npm and not subprocess.run([node, "-e", "require('playwright')"], env=nenv, capture_output=True).returncode:
        print("Браузер")
        # Блокировка с адреса стенда — снять для прогона в браузере: новый стенд
        stand.terminate()
        stand.wait(10)
        stand = subprocess.Popen([sys.executable, os.path.join(HERE, "web_stand.py")], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ready = ""
        for _ in range(240):
            line = stand.stdout.readline()
            if line.startswith("READY") or (not line and stand.poll() is not None):
                ready = line
                break
        _, PORT, BASE, USER, PASSWORD, ROOT = ready.split()
        out = os.environ.get("AWG_WEB_SHOTS") or os.path.join(ROOT, "..", "shots")
        os.makedirs(out, exist_ok=True)
        r = subprocess.run([node, os.path.join(HERE, "web_drive.js"), PORT, BASE, USER, PASSWORD, out],
                           env=nenv, capture_output=True, text=True, timeout=600)
        lines = r.stdout.strip().splitlines()
        for ln in lines:
            if ln.startswith(("OK ", "FAIL ")):
                chk(ln.split(" ", 1)[1], ln.startswith("OK "))
        errs = [ln for ln in lines if ln.startswith("ERR ")]
        chk("в браузере: без ошибок на странице и без внешних запросов", r.returncode == 0 and not errs,
            "\n".join(errs) or r.stderr[-800:])
    else:
        print("Браузер пропущен: нет node/Playwright")
finally:
    stand.terminate()

print(f"\nпроверок: {checks}, провалов: {fails}")
sys.exit(1 if fails else 0)
