"""
test_regress_f2f3.py — регрессии после ревью v1.2.36–v1.2.39: мягкий лимит у
заблокированного сроком (Ф2) и повреждённые числовые метки клиента (Ф3).

Каждая проверка описывает правильное поведение; «Ф…» в начале — новая проверка,
без кода — страховочная (уже верное поведение не должно сломаться).

Запуск:  python3 tests/test_regress_f2f3.py [путь/к/awg2.sh]
"""
import os
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sandbox import *  # noqa: E402,F401,F403

CONF = os.path.join(ROOT, "etc/amnezia/amneziawg/awg0.conf")
SUSP = bash('echo "$EXPIRE_SUSPEND_IP"')[1].strip()
API_WRAP = api_wrapper()
BASE = OLD20.replace("# expires=1\n", "")        # bob без срока: сценарии не мешают друг другу
OVER = {"alice": (1000 + 3 * 2**20, 2000), "bob": (10, 10)}
MB = 2**20


def api(*args):
    r = subprocess.run([API_WRAP, *args], capture_output=True, text=True, env=ENV, timeout=120)
    lines = r.stdout.strip().splitlines()
    try:
        res = json.loads(lines[-1]) if lines else {}
    except ValueError:
        res = {"raw": r.stdout}
    res["_err"] = r.stderr
    return res


def clients():
    r = api("clients", "list")
    return r.get("data") if r.get("ok") else None


def cl(name):
    return next((c for c in clients() or [] if c.get("name") == name), {})


def pubs():
    out = {}
    for blk in open(CONF, encoding="utf-8").read().split("[Peer]")[1:]:
        nm = blk.strip().splitlines()[0].lstrip("# ").strip()
        m = re.search(r"^PublicKey\s*=\s*(\S+)", blk, re.M)
        if m:
            out[nm] = m.group(1)
    return out


def dump_with(counters):
    p = pubs()
    with open(AWG_DUMP, "w") as f:
        f.write("priv\tpub\t51820\toff\n")
        for n, (rx, tx) in counters.items():
            f.write(f"{p[n]}\t(none)\t1.2.3.4:5\t10.0.0.0/32\t0\t{rx}\t{tx}\t25\n")


def nb(code):
    """bash с перехватом отправок в Telegram (тело — в журнал вызовов)."""
    return bash('curl() { cat >> "$CALLS"; echo >> "$CALLS"; }; ' + code)


def msgs():
    return re.findall(r'text=(.*)"\s*$', calls(), re.M)


def peer(name):
    for blk in open(CONF, encoding="utf-8").read().split("[Peer]")[1:]:
        if blk.strip().splitlines()[0].lstrip("# ").strip() == name:
            return blk
    return ""


def meta(name, key):
    m = re.search(rf"^#\s*{key}=(.*?)\s*$", peer(name), re.M)
    return m.group(1) if m else None


def blocked(name):
    return f"AllowedIPs = {SUSP}" in peer(name)


def speed_state():
    return bash('cat "$EXPIRE_STATE_DIR/speed" 2>/dev/null')[1]


def expire_log():
    p = os.path.join(ROOT, "expire.log")
    return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""


def fresh(conf_text=BASE, extra_meta=None):
    text = conf_text
    for name, lines in (extra_meta or {}).items():
        text = text.replace(f"# {name}\n", f"# {name}\n" + "".join(f"# {ln}\n" for ln in lines), 1)
    with open(CONF, "w", encoding="utf-8") as f:
        f.write(text)
    for n in ("alice", "bob"):
        with open(os.path.join(ROOT, "root", n + "_awg2.conf"), "w") as f:
            f.write("[Interface]\nPrivateKey = X\n")
    bash('rm -rf "$TRAFFIC_DB" "$EXPIRE_STATE_DIR"; : > "$EXPIRE_LOG"; rm -f "$CALLS.tcroot"')
    with open(LINKS, "w") as f:
        f.write("awg0\n")
    with open(os.path.join(ROOT, "bot.conf"), "w") as f:
        f.write('BOT_TOKEN="1:AA"\nADMIN_ID=11\n')
    dump_with({"alice": (1000, 2000), "bob": (10, 10)})
    bash("traffic_tick 1")                       # первый проход запоминает счётчики
    reset_calls()


def expire_now(name):
    bash(f'py meta-set "$SERVER_CONF" {name} expires $(( $(date +%s) - 60 ))')
    nb("expire_check_run")


def soft_slowed_then_expired():
    """alice: мягкий лимит 2 Мбит/с исчерпан (замедлена), затем истёк срок."""
    fresh()
    api("client", "limit-mode", "alice", "2")
    api("client", "limit", "alice", "1M", "total")
    dump_with(OVER)
    nb("traffic_tick")
    expire_now("alice")
    reset_calls()


def hard_blocked_then_expired():
    """alice: блок за трафик (режим «блокировать»), затем истёк срок."""
    fresh()
    api("client", "limit", "alice", "1M", "total")
    dump_with(OVER)
    nb("traffic_tick")
    expire_now("alice")
    reset_calls()


print(f"Python {sys.version.split()[0]}; заглушка блокировки: {SUSP}")

# ══ Ф2: мягкий лимит и блокировка сроком ═════════════════════════
print("\nФ2 — мягкий лимит у заблокированного сроком")

# Страховка: обычный путь мягкого лимита у активного клиента
fresh()
api("client", "limit-mode", "alice", "2")
api("client", "limit", "alice", "1M", "total")
dump_with(OVER)
nb("traffic_tick")
a = cl("alice")
chk("активный клиент: исчерпал — замедлен, одно сообщение «замедлен до 2»",
    a.get("slowed") and not a.get("blocked") and len([m for m in msgs() if "замедлен до 2" in m]) == 1, [a, msgs()])
reset_calls()
nb("client_limit_set alice off >/dev/null")
chk("активный клиент: лимит снят — «снова полная скорость»", any("снова полная скорость" in m for m in msgs()), msgs())

# A: замедлен → истёк срок
soft_slowed_then_expired()
a = cl("alice")
chk("Ф2.1 замедлен → истёк срок: заблокирован сроком, в списке клиентов не «замедлен»",
    a.get("blocked") and a.get("blocked_by") == "expire" and not a.get("slowed"), a)
nb("client_limit_reset alice >/dev/null")
chk("Ф2.2 замедлен → истёк → новый период: нет «снова полная скорость», пока заблокирован",
    blocked("alice") and not any("полная скорость" in m for m in msgs()), [msgs(), peer("alice")])
chk("Ф2.2 … и в журнале нет «unslow» у заблокированного", "unslow: alice" not in expire_log(), expire_log()[-300:])

# A′: замедлен → истёк → продлён, лимит всё ещё исчерпан
soft_slowed_then_expired()
r = api("client", "expire", "alice", "+30d")
chk("продление снимает блокировку сроком", r.get("ok") and not blocked("alice"), [r, peer("alice")])
chk("Ф2.3 продление замедленного: замедление действует сразу, без окна полной скорости до прохода таймера",
    re.search(r"^10\.23\.45\.2/32\t2$", speed_state(), re.M) is not None, [speed_state(), meta("alice", "slowed_by")])
reset_calls()
nb("traffic_tick")
chk("Ф2.3 продление замедленного: следующий проход таймера — без сообщений", msgs() == [], msgs())
chk("продление замедленного: после прохода таймера замедление на месте",
    re.search(r"^10\.23\.45\.2/32\t2$", speed_state(), re.M) is not None and cl("alice").get("slowed"), speed_state())

# B: блок за трафик → истёк → переключение на «замедлять»
hard_blocked_then_expired()
nb("client_limit_mode alice 2 >/dev/null")
a = cl("alice")
chk("блок за трафик → истёк → limit-mode 2: блокировку держит срок (правило #10)",
    a.get("blocked") and a.get("blocked_by") == "expire", a)
chk("Ф2.4 … без сообщения «замедлен» заблокированному", not any("замедлен" in m for m in msgs()), msgs())
chk("Ф2.4 … в списке клиентов не «замедлен»", not a.get("slowed"), a)
reset_calls()
r = api("client", "expire", "alice", "+30d")
chk("Ф2.5 B → продление: замедление до 2 Мбит/с сразу", not blocked("alice")
    and re.search(r"^10\.23\.45\.2/32\t2$", speed_state(), re.M) is not None, [r.get("ok"), speed_state()])
nb("traffic_tick")
chk("B → продление: проход таймера не блокирует (режим «замедлять») и не шлёт «заблокирован»",
    not blocked("alice") and not any("заблокирован" in m for m in msgs()), [msgs(), peer("alice")])

# Истёк и замедлен → limit-mode block → продление
soft_slowed_then_expired()
nb("client_limit_mode alice block >/dev/null")
chk("истёк и замедлен → limit-mode block: без сообщений, замедление снято",
    msgs() == [] and meta("alice", "slowed_by") in (None, ""), [msgs(), peer("alice")])
r = api("client", "expire", "alice", "+30d")
chk("Ф3.26 … затем продление: сразу блок за трафик (не после прохода таймера), с предупреждением",
    blocked("alice") and meta("alice", "blocked_by") == "traffic" and "лимит" in (r.get("log") or ""),
    [peer("alice"), (r.get("log") or "")[-200:]])
reset_calls()
nb("traffic_tick")
chk("… следующий проход таймера: по-прежнему блок за трафик, без повторных сообщений",
    blocked("alice") and meta("alice", "blocked_by") == "traffic" and msgs() == [], [msgs(), peer("alice")])

# Истёк и замедлен → лимит снят
soft_slowed_then_expired()
nb("client_limit_set alice off >/dev/null")
chk("Ф2.7 истёк и замедлен → лимит снят: замедление снято без «снова полная скорость»",
    meta("alice", "slowed_by") in (None, "") and not any("полная скорость" in m for m in msgs()), [msgs(), peer("alice")])

# ══ Ф3: повреждённые метки ═══════════════════════════════════════
print("\nФ3 — повреждённые числовые метки клиента")
BAD = ["²", "①", "abc", "-1"]

# Обработка остальных клиентов не останавливается
for key in ("speed", "limit_slow", "expires", "limit"):
    for val in BAD:
        fresh(extra_meta={"bob": [f"{key}={val}"]})
        res = {}
        for cmd, code in (("speed-plan", 'py speed-plan "$SERVER_CONF" "$EXPIRE_SUSPEND_IP"'),
                          ("traffic-tick", 'tr=$(mktemp); py traffic-tick "$SERVER_CONF" "$EXPIRE_SUSPEND_IP" "$TRAFFIC_DB" "$tr" "" 1'),
                          ("expire-check", 'py expire-check "$SERVER_CONF" "$EXPIRE_SUSPEND_IP" "$EXPIRE_STATE_DIR"')):
            res[cmd] = bash(code + ' >/dev/null 2>&1; echo $?')[1].strip()
        res["clients list"] = clients() is not None
        chk(f"Ф3.1 bob: {key}={ascii(val)} — speed-plan, traffic-tick, expire-check и список клиентов работают",
            all(v == "0" for k, v in res.items() if k != "clients list") and res["clients list"], res)

# Лимиты и сроки остальных применяются
for key, val in (("limit_slow", "①"), ("expires", "²"), ("speed", "²"), ("limit", "①/month")):
    fresh(extra_meta={"bob": [f"{key}={val}"]})
    api("client", "limit", "alice", "1M", "total")
    dump_with(OVER)
    nb("traffic_tick")
    chk(f"Ф3.2 bob: {key}={ascii(val)} — alice за превышение лимита блокируется", blocked("alice")
        and meta("alice", "blocked_by") == "traffic", peer("alice"))
    fresh(extra_meta={"bob": [f"{key}={val}"]})
    expire_now("alice")
    chk(f"Ф3.3 bob: {key}={ascii(val)} — истёкшая alice блокируется сроком", blocked("alice"), peer("alice"))

# Fail-closed по меткам
for val in ("²", "abc", "-1"):
    fresh(extra_meta={"bob": [f"expires={val}"]})
    nb("expire_check_run")
    b = cl("bob")
    chk(f"Ф3.4 bob: expires={ascii(val)} — заблокирован отдельной причиной (meta), не бессрочный",
        blocked("bob") and meta("bob", "blocked_by") == "meta", [peer("bob"), b])
for val in ("①/month", "abc", "5G/month", "-1/total"):
    fresh(extra_meta={"bob": [f"limit={val}"]})
    nb("traffic_tick")
    chk(f"Ф3.5 bob: limit={ascii(val)} — заблокирован (meta), а не «без лимита»",
        blocked("bob") and meta("bob", "blocked_by") == "meta", peer("bob"))
for val in ("①", "abc"):
    fresh(extra_meta={"bob": [f"limit_slow={val}"]})
    api("client", "limit", "bob", "1M", "total")
    dump_with({"alice": (1000, 2000), "bob": (10 + 3 * MB, 10)})
    nb("traffic_tick")
    chk(f"Ф3.6 bob: limit_slow={ascii(val)}, лимит исчерпан — блок, как в режиме «блокировать»",
        blocked("bob") and meta("bob", "blocked_by") == "traffic" and not cl("bob").get("slowed"), peer("bob"))
fresh(extra_meta={"alice": ["speed=5"], "bob": ["speed=²"]})
nb("traffic_tick")
chk("Ф3.7 bob: speed=² — у alice своя скорость 5 Мбит/с применяется", re.search(r"^10\.23\.45\.2/32\t5$", speed_state(), re.M)
    is not None, [speed_state(), expire_log()[-200:]])
chk("Ф3.7 bob: speed=² — не блокируется и не получает произвольной скорости",
    not blocked("bob") and "10.23.45.3/32" not in speed_state(), [speed_state(), peer("bob")])
chk("Ф3.7 bob: speed=² — предупреждение о повреждённой метке в журнале",
    re.search(r"bob.*speed|speed.*bob", expire_log()) is not None and "поврежд" in expire_log(), expire_log()[-300:])
chk("Ф3.8 bad_meta в списке клиентов: bob — [speed]", (cl("bob").get("bad_meta") or []) == ["speed"], cl("bob"))

# Отсутствующие, пустые и с пробелами — как раньше / терпимо
fresh(extra_meta={"bob": ["expires="]})
nb("expire_check_run")
chk("пустой expires= — бессрочный, как раньше", not blocked("bob"), peer("bob"))
fresh(extra_meta={"bob": [f"expires= {int(time.time()) - 60}"]})
nb("expire_check_run")
chk("Ф3.9 expires с пробелом перед числом — срок действует (истёкший блокируется сроком)",
    blocked("bob") and meta("bob", "blocked_by") in (None, ""), peer("bob"))

# Переходы состояния блокировки meta
fresh(extra_meta={"bob": ["limit=abc"]})
nb("traffic_tick")
r = api("client", "expire", "bob", "+30d")
nb("traffic_tick")
chk("Ф3.10 блок meta: продление срока его не снимает", blocked("bob") and meta("bob", "blocked_by") == "meta", peer("bob"))
nb("client_limit_reset bob >/dev/null; traffic_tick")
chk("Ф3.11 блок meta: новый период (сброс счётчика) его не снимает", blocked("bob") and meta("bob", "blocked_by") == "meta",
    peer("bob"))
nb("clients_purge_blocked >/dev/null")
chk("Ф3.12 блок meta: «Удалить с истёкшим сроком» bob не удаляет (и он по-прежнему заблокирован)",
    "bob" in pubs() and blocked("bob") and meta("bob", "blocked_by") == "meta", list(pubs()))
api("client", "limit", "alice", "1M", "total")
dump_with(OVER)
nb("traffic_tick")
chk("Ф3.13 блок meta у bob: лимит alice применяется", blocked("alice") and meta("alice", "blocked_by") == "traffic",
    peer("alice"))
pre = blocked("bob") and meta("bob", "blocked_by") == "meta"
nb("client_limit_set bob off >/dev/null; traffic_tick")
chk("Ф3.14 блок meta: метка исправлена (лимит снят) — блокировка снимается (до этого была)",
    pre and not blocked("bob") and meta("bob", "blocked_by") in (None, ""), [pre, peer("bob")])
fresh(extra_meta={"bob": ["expires=abc"]})
nb("expire_check_run")
pre = blocked("bob") and meta("bob", "blocked_by") == "meta"
r = api("client", "expire", "bob", "+30d")
nb("expire_check_run; traffic_tick")
chk("Ф3.15 блок meta по expires: новый корректный срок — блокировка снимается (до этого была)",
    pre and r.get("ok") and not blocked("bob") and meta("bob", "blocked_by") in (None, ""), [pre, r.get("ok"), peer("bob")])


# Восстановление недоверенного бэкапа
def tampered_backup(inject):
    src = (api("backup", "create").get("data") or {}).get("path", "")
    x = os.path.join(TMP, "bk_x")
    shutil.rmtree(x, ignore_errors=True)
    with tarfile.open(src) as t:
        t.extractall(x, filter="tar")
    for d, _, files in os.walk(x):
        if "awg0.conf" in files:
            p = os.path.join(d, "awg0.conf")
            s = open(p, encoding="utf-8").read()
            for name, lines in inject.items():
                s = s.replace(f"# {name}\n", f"# {name}\n" + "".join(f"# {ln}\n" for ln in lines), 1)
            open(p, "w", encoding="utf-8").write(s)
    dst = os.path.join(TMP, "untrusted.tar.gz")
    with tarfile.open(dst, "w:gz") as t:
        for n in sorted(os.listdir(x)):
            t.add(os.path.join(x, n), arcname=n)
    return dst


fresh()
api("client", "limit", "alice", "1M", "total")
bk = tampered_backup({"bob": ["limit_slow=①", "speed=²", "limit=abc", "expires=²"]})
r = api("backup", "restore", bk)
chk("восстановление подменённого бэкапа проходит", r.get("ok"), r.get("error"))
chk("Ф3.16 восстановление: предупреждение о повреждённых метках bob",
    re.search(r"поврежд\w*.*bob|bob.*поврежд", (r.get("log") or "") + (r.get("_err") or "")) is not None,
    (r.get("log") or "")[-400:])
chk("Ф3.17 после восстановления: список клиентов работает", clients() is not None, api("clients", "list").get("error"))
dump_with(OVER)
nb("expire_check_run")
chk("Ф3.18 после восстановления: лимит alice применяется, bob заблокирован (meta)",
    blocked("alice") and blocked("bob") and meta("bob", "blocked_by") == "meta", [peer("alice"), peer("bob")])
n1 = expire_log().count("\n")
for _ in range(3):
    nb("expire_check_run")
chk("Ф3.19 повреждённые метки: журнал не растёт на каждом проходе таймера", expire_log().count("\n") == n1,
    expire_log().splitlines()[-4:])


# ══ Дополнительно (2026-10-21) ═══════════════════════════════════
TDB = bash('echo "$TRAFFIC_DB"')[1].strip()


def new_month():
    """Весь учтённый трафик — 40 дней назад: для лимита «за месяц» настал новый месяц."""
    d = json.load(open(TDB))
    merged = {}
    for v in (d.get("days") or {}).values():
        for p, (rx, tx) in v.items():
            a = merged.get(p) or [0, 0]
            merged[p] = [a[0] + rx, a[1] + tx]
    d["days"] = {time.strftime("%Y-%m-%d", time.localtime(time.time() - 40 * 86400)): merged}
    json.dump(d, open(TDB, "w"))


def inject(name, lines):
    """Метки в конфиг напрямую, без прохода таймера."""
    s = open(CONF, encoding="utf-8").read()
    s = s.replace(f"# {name}\n", f"# {name}\n" + "".join(f"# {ln}\n" for ln in lines), 1)
    open(CONF, "w", encoding="utf-8").write(s)


def rate(ip):
    m = re.search(rf"^{re.escape(ip)}/32\t(\d+)$", speed_state(), re.M)
    return int(m.group(1)) if m else None


print("\nФ2 — месячный сброс и смена режима лимита")
fresh()
api("client", "limit-mode", "alice", "2")
api("client", "limit", "alice", "1M", "month")
dump_with(OVER)
nb("traffic_tick")
pre = cl("alice").get("slowed") and rate("10.23.45.2") == 2
reset_calls()
new_month()
nb("traffic_tick")
chk("активный замедленный: новый месяц — одно «снова полная скорость», замедление снято",
    pre and len([m for m in msgs() if "полная скорость" in m]) == 1 and rate("10.23.45.2") is None, [pre, msgs()])

fresh()
api("client", "limit-mode", "alice", "2")
api("client", "limit", "alice", "1M", "month")
dump_with(OVER)
nb("traffic_tick")
expire_now("alice")
reset_calls()
new_month()
nb("traffic_tick")
chk("Ф2.8 замедлен → истёк → новый месяц: без сообщений, заблокирован сроком, метка замедления снята",
    msgs() == [] and blocked("alice") and meta("alice", "slowed_by") in (None, ""), [msgs(), peer("alice")])
api("client", "expire", "alice", "+30d")
chk("… затем продление: полная скорость", not blocked("alice") and rate("10.23.45.2") is None, speed_state())

fresh()
api("client", "limit", "alice", "1M", "total")
dump_with(OVER)
nb("traffic_tick")
reset_calls()
nb("client_limit_mode alice 2 >/dev/null")
chk("активный: блок за трафик → limit-mode 2 — разблокирован и сразу замедлен, одно сообщение «замедлен до 2»",
    not blocked("alice") and cl("alice").get("slowed") and rate("10.23.45.2") == 2
    and len([m for m in msgs() if "замедлен до 2" in m]) == 1 and len(msgs()) == 1, [msgs(), speed_state()])
reset_calls()
nb("client_limit_mode alice block >/dev/null")
chk("активный замедленный → limit-mode block — блок за трафик, одно сообщение, без «полная скорость»",
    blocked("alice") and meta("alice", "blocked_by") == "traffic" and len(msgs()) == 1 and "исчерпан лимит" in msgs()[0],
    msgs())
reset_calls()
nb("client_limit_mode alice 5 >/dev/null")
chk("… и снова limit-mode 5 — разблокирован, замедлен до 5", not blocked("alice") and rate("10.23.45.2") == 5
    and len([m for m in msgs() if "замедлен до 5" in m]) == 1, [msgs(), speed_state()])

print("\nФ3 — несколько повреждённых меток, исправление по одной")
ALL4 = ["expires", "limit", "limit_slow", "speed"]
fresh()
inject("bob", ["expires=²", "limit=abc", "limit_slow=①", "speed=²"])
reset_calls()
nb("expire_check_run")
b = cl("bob")
chk("Ф3.20 bob: четыре повреждённые метки — заблокирован (meta), bad_meta — все четыре",
    blocked("bob") and meta("bob", "blocked_by") == "meta" and sorted(b.get("bad_meta") or []) == sorted(ALL4),
    [peer("bob"), b])
chk("Ф3.20 … сообщений два: блокировка (срок, лимит) и предупреждение (скорость, режим)",
    len(msgs()) == 2 and any("заблокирован" in m and "expires, limit" in m for m in msgs())
    and any("limit_slow, speed" in m for m in msgs()), msgs())
chk("Ф3.20 … alice не задета", not blocked("alice") and cl("alice").get("bad_meta") == [], peer("alice"))
reset_calls()
nb("expire_check_run; expire_check_run")
chk("Ф3.20 повторные проходы таймера — без сообщений", msgs() == [], msgs())
nb("client_limit_set bob off >/dev/null")
chk("Ф3.21 лимит исправлен (снят), срок ещё повреждён — блок meta держится",
    blocked("bob") and meta("bob", "blocked_by") == "meta", peer("bob"))
reset_calls()
r = api("client", "expire", "bob", "+30d")
b = cl("bob")
chk("Ф3.21 исправлен и срок — разблокирован, одно «разблокирован: метки исправлены»",
    r.get("ok") and not blocked("bob") and b.get("blocked_by") is None
    and len([m for m in msgs() if "метки исправлены" in m]) <= 1, [r.get("ok"), peer("bob"), msgs()])
chk("Ф3.21 … повреждённые скорость и режим лимита остаются в bad_meta, но не блокируют",
    sorted(b.get("bad_meta") or []) == ["limit_slow", "speed"] and rate("10.23.45.3") is None, b)
api("client", "limit", "bob", "1M", "total")
dump_with({"alice": (1000, 2000), "bob": (10 + 3 * MB, 10)})
nb("traffic_tick")
chk("Ф3.22 повреждённый limit_slow: исчерпал — заблокирован за трафик, а не замедлен",
    blocked("bob") and meta("bob", "blocked_by") == "traffic" and not cl("bob").get("slowed"), peer("bob"))
api("client", "limit-mode", "bob", "2")
chk("Ф3.22 режим задан заново — разблокирован и замедлен до 2 (повреждённая скорость не мешает)",
    not blocked("bob") and cl("bob").get("slowed") and rate("10.23.45.3") == 2, [peer("bob"), speed_state()])
api("client", "speed", "bob", "off")
chk("Ф3.22 скорость задана заново — bad_meta пуст", cl("bob").get("bad_meta") == [], cl("bob"))

fresh()
api("client", "limit", "bob", "1M", "total")
dump_with({"alice": (1000, 2000), "bob": (10 + 3 * MB, 10)})
nb("traffic_tick")
nb('py meta-set "$SERVER_CONF" bob expires "²"; expire_check_run')
pre = meta("bob", "blocked_by") == "meta"
nb('py meta-set "$SERVER_CONF" bob expires ""')
bash('py expire-check "$SERVER_CONF" "$EXPIRE_SUSPEND_IP" "$EXPIRE_STATE_DIR" >/dev/null')
chk("метка исправлена, лимит исчерпан: проход сроков блокировку не снимает", blocked("bob"), [pre, peer("bob")])
reset_calls()
nb("traffic_tick")
chk("… проход трафика: заблокирован уже за трафик", blocked("bob") and meta("bob", "blocked_by") == "traffic",
    [msgs(), peer("bob")])

print("\nФ3 — повреждённая скорость у ограниченного клиента")
fresh(extra_meta={"bob": ["speed=5"]})
nb("traffic_tick")
pre = rate("10.23.45.3") == 5
nb('py meta-set "$SERVER_CONF" bob speed "²"')
reset_calls()
nb("traffic_tick")
chk("Ф3.23 скорость испорчена: ограничение не действует — и об этом одно сообщение «скорость не ограничивается»",
    pre and rate("10.23.45.3") is None
    and len([m for m in msgs() if "bob" in m and "скорость не ограничивается" in m]) == 1, [pre, msgs(), speed_state()])
chk("Ф3.23 … и строка в журнале", "badmeta: bob (повреждена метка speed" in expire_log(), expire_log()[-300:])
reset_calls()
n1 = expire_log().count("\n")
nb("traffic_tick; traffic_tick")
chk("Ф3.23 повторных предупреждений нет — ни в Telegram, ни в журнале",
    msgs() == [] and expire_log().count("\n") == n1, [msgs(), expire_log().splitlines()[-3:]])
nb("client_speed_set bob 3 >/dev/null")
chk("Ф3.23 скорость задана заново — 3 Мбит/с, bad_meta пуст",
    rate("10.23.45.3") == 3 and cl("bob").get("bad_meta") == [], [speed_state(), cl("bob")])

# Строки журнала meta/unmeta/badmeta — в формате ленты событий панели (parseEvents в app.js):
# «ДАТА ВРЕМЯ событие: имя (подробности)»; имя — без скобок, подробности — в скобках
EV = re.compile(r"^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):\d\d (\w+): ?([^(]*?)\s*(?:\((.*)\))?\s*$")
fresh()
inject("bob", ["limit=abc", "speed=²"])
nb("expire_check_run")
nb("client_limit_set bob off >/dev/null; client_speed_set bob off >/dev/null; traffic_tick")
evs = [(m.group(6), m.group(7), m.group(8)) for m in map(EV.match, expire_log().splitlines())
       if m and m.group(6) in ("meta", "unmeta", "badmeta")]
chk("Ф3.32 журнал: meta, badmeta и unmeta разбираются лентой панели, имя — bob",
    [e[0] for e in evs] == ["meta", "badmeta", "unmeta"] and all(e[1] == "bob" and e[2] for e in evs), evs)
chk("Ф3.32 … подробности: причина у meta и badmeta, итог у unmeta (не повтор заголовка «метки исправлены»)",
    all("повреждена метка" in e[2] for e in evs if e[0] != "unmeta")
    and all("исправлены" not in e[2] for e in evs if e[0] == "unmeta"), evs)
fresh()
inject("bob", ["expires=abc"])
nb("expire_check_run")
reset_calls()
n1 = len(expire_log().splitlines())
nb("client_expire_set bob $(( $(date +%s) + 86400 )) >/dev/null")
new = expire_log().splitlines()[n1:]
chk("Ф3.33 продление снимает блокировку meta — одна строка unmeta в журнале, без Telegram",
    [ln for ln in new if EV.match(ln) and EV.match(ln).group(6) == "unmeta" and EV.match(ln).group(7) == "bob"] == new
    and len(new) == 1 and msgs() == [] and not blocked("bob"), [new, msgs()])

print("\nПути разблокировки: ни одной синхронизации awg0 с настоящим адресом, пока лимит исчерпан")
SYNCLOG = os.path.join(TMP, "synclog")


def synced(code, name):
    """code в bash; каждая синхронизация awg0 (меню/API и таймер) записывает
    AllowedIPs клиента name в момент синхронизации. → (список, вывод)."""
    open(SYNCLOG, "w").close()
    rec = (f'_rec() {{ py peers "$SERVER_CONF" | awk -F"\\t" -v n={name} \'$1 == n {{print $3}}\' >> {SYNCLOG}; }}; '
           '_expire_apply() { _rec; }; _expire_sync() { _rec; }; ')
    r = nb(rec + code)
    return open(SYNCLOG).read().split(), r[1] + r[2]


def over_month_then(name, how):
    """name израсходовал 3 МБ в этом месяце, затем how: expire — истёк срок,
    meta — повреждена метка срока; потом лимит 1 МБ/мес (уже исчерпан)."""
    fresh()
    big = {"alice": (1000, 2000), "bob": (10, 10)}
    big[name] = (10 + 3 * MB, 10)
    dump_with(big)
    nb("traffic_tick")
    if how == "expire":
        expire_now(name)
    else:
        nb(f'py meta-set "$SERVER_CONF" {name} expires abc; expire_check_run')
    nb(f"client_limit_set {name} 1M month >/dev/null")
    reset_calls()


for how in ("expire", "meta"):
    for op in ("client_expire_set {n} $(( $(date +%s) + 86400 ))", "client_expire_clear {n}"):
        over_month_then("bob", how)
        pre = blocked("bob") and meta("bob", "blocked_by") == ("meta" if how == "meta" else None)
        seen, out = synced(op.format(n="bob"), "bob")
        word = op.split()[0]
        chk(f"Ф3.26 {how} → {word}: лимит исчерпан — ни одной синхронизации с настоящим адресом",
            pre and seen and all(s == SUSP for s in seen), [pre, seen, peer("bob")])
        chk(f"Ф3.26 {how} → {word}: сразу заблокирован за трафик, с предупреждением",
            blocked("bob") and meta("bob", "blocked_by") == "traffic" and "лимит" in out, [peer("bob"), out[-200:]])
        seen, _ = synced("traffic_tick", "bob")
        chk(f"Ф3.26 {how} → {word}: следующий проход таймера адрес не возвращает",
            all(s == SUSP for s in seen) and blocked("bob"), seen)

over_month_then("bob", "expire")
nb("client_limit_mode bob 2 >/dev/null")
seen, out = synced("client_expire_set bob $(( $(date +%s) + 86400 ))", "bob")
chk("Ф3.27 мягкий лимит, истёк и исчерпан → продление: сразу замедлен до 2, без окна полной скорости",
    not blocked("bob") and meta("bob", "slowed_by") == "traffic" and rate("10.23.45.3") == 2, [peer("bob"), speed_state()])

# Лимит в норме — продление и снятие срока возвращают адрес, как раньше
for how in ("expire", "meta"):
    fresh()
    if how == "expire":
        expire_now("bob")
    else:
        nb('py meta-set "$SERVER_CONF" bob expires abc; expire_check_run')
    seen, _ = synced("client_expire_set bob $(( $(date +%s) + 86400 ))", "bob")
    chk(f"{'Ф3.29 ' if how == 'meta' else ''}{how} → продление при лимите в норме: адрес возвращён",
        not blocked("bob") and seen[-1:] == ["10.23.45.3/32"],
        [seen, peer("bob")])

# Метка исправлена проходом таймера, а лимит исчерпан: адрес не возвращается ни на миг
over_month_then("bob", "meta")
nb('py meta-set "$SERVER_CONF" bob expires ""')
seen, _ = synced("expire_check_run", "bob")
chk("Ф3.28 метка исправлена руками, лимит исчерпан: проход таймера — блок за трафик без окна",
    all(s == SUSP for s in seen) and meta("bob", "blocked_by") == "traffic", [seen, peer("bob")])

print("\nСовместимость: состояния, оставленные v1.2.38–v1.2.40, в бэкапе")
fresh()
api("client", "limit-mode", "alice", "2")
api("client", "limit", "alice", "1M", "total")
api("client", "limit", "bob", "1M", "total")
dump_with({"alice": OVER["alice"], "bob": (10 + 3 * MB, 10)})
nb("traffic_tick")
expire_now("alice")
if meta("alice", "slowed_by") != "traffic":
    inject("alice", ["slowed_by=traffic"])      # так v1.2.38–v1.2.40 оставляли истёкшего замедленного
bk = (api("backup", "create").get("data") or {}).get("path", "")
r = api("backup", "restore", bk)
chk("старый бэкап: восстановление без предупреждений о метках", r.get("ok") and "поврежд" not in (r.get("log") or ""),
    (r.get("log") or "")[-300:])
reset_calls()
nb("expire_check_run")
a, b = cl("alice"), cl("bob")
chk("старый бэкап: alice заблокирована сроком и не «замедлена», bob — за трафик, сообщений нет",
    a.get("blocked_by") == "expire" and not a.get("slowed") and b.get("blocked_by") == "traffic" and msgs() == [],
    [a, b, msgs()])
nb("clients_purge_blocked >/dev/null")
chk("старый бэкап: «Удалить с истёкшим сроком» удаляет alice и оставляет bob", list(pubs()) == ["bob"], list(pubs()))

summary()
