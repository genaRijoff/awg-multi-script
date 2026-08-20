"""
test_mimicry.py — метка профиля мимикрии "# mimicry=" в peer-блоке.

Профиль CPS по байтам I1 не восстанавливается: сигнатуры пересекаются
(sip и quic оба начинаются с 0x4..), а stun/webrtc/ntp/rtp/ssdp неотличимы
вовсе — поэтому awg2 и бот пишут его явной меткой. Тест проверяет, что:

  • метка не подменяет имя клиента при разборе peer-блока;
  • она переживает срок действия, заметку и переименование;
  • add_client и change_client_mimicry её пишут и обновляют;
  • смена профиля не задевает awg-параметры 2.0/3.0/3.1 в конфиге клиента;
  • bash-функции awg2.sh читают ту же метку.

awg подменяется заглушкой в PATH — тест не трогает реальный сервер.

Запуск:  python3 tests/test_mimicry.py [путь/к/awg2.sh]
Выход:   0 — всё сошлось, 1 — есть провалы.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
AWG2 = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                       else os.path.join(_HERE, "..", "awg2.sh"))
BOT_PKG = os.path.abspath(os.path.join(_HERE, "..", "awg_bot"))

fails = 0
checks = 0


def chk(label, expected, actual):
    global fails, checks
    checks += 1
    if expected == actual:
        print(f"  OK   {label}")
    else:
        fails += 1
        print(f"  FAIL {label}\n       ожидалось: {expected!r}\n       получено:  {actual!r}")


def chk_true(label, cond, hint=""):
    chk(label, True, bool(cond) or (print(f"       {hint}") if hint else False) or False)


# ───────────────────────── окружение ─────────────────────────
TMP = tempfile.mkdtemp(prefix="awg-mimicry-test.")
BIN = os.path.join(TMP, "bin")
ETC = os.path.join(TMP, "etc")
CLI = os.path.join(TMP, "clients")
for d in (BIN, ETC, CLI):
    os.makedirs(d)
SERVER_CONF = os.path.join(ETC, "awg0.conf")

# Заглушка awg: ключи фиксированной формы (44 символа base64), остальное — no-op.
AWG_STUB = r"""#!/usr/bin/env bash
case "$1" in
  genkey|genpsk) head -c 32 /dev/urandom | base64 ;;
  pubkey)        head -c 32 /dev/urandom | base64 ;;
  show)          exit 1 ;;
  set|syncconf)  exit 0 ;;
  *)             exit 0 ;;
esac
"""
with open(os.path.join(BIN, "awg"), "w") as f:
    f.write(AWG_STUB)
os.chmod(os.path.join(BIN, "awg"), 0o755)
with open(os.path.join(BIN, "awg-quick"), "w") as f:
    f.write("#!/usr/bin/env bash\nexit 0\n")
os.chmod(os.path.join(BIN, "awg-quick"), 0o755)
# Бот ищет генератор CPS в бинаре awg2 — подкладываем сам скрипт.
shutil.copy2(AWG2, os.path.join(BIN, "awg2"))

os.environ["PATH"] = BIN + os.pathsep + os.environ.get("PATH", "")
os.environ["AWG_SERVER_CONF"] = SERVER_CONF
os.environ["AWG_CLIENT_DIR"] = CLI
os.environ["AWG_BOT_CONF"] = os.path.join(ETC, "awg-bot.conf")
os.environ["AWG_NOTES_FILE"] = os.path.join(ETC, "notes.json")

# Конфиг сервера AWG 3.1: параметры 3.x обязаны пережить смену мимикрии,
# иначе клиент после смены профиля молча уедет на 2.0 и не подключится.
SRV = """# AWG_PROFILE=pro
# AmneziaWG Toolza — AWG 3.1 server config
# Region: world
# AWG_PROTO=3.1
# AWG_OBF_LEVEL=3
# AWG_MIMICRY=quic
[Interface]
PrivateKey = 4FZoPwYBIkc4ZP5+2vX6c1J5C1p1s3vDqk8UlG2xVFo=
Address = 10.9.9.1/24
ListenPort = 51820
MTU = 1320
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890
HeaderProtectionKey = c2VjcmV0LWtleS1mb3ItdGVzdC1vbmx5LTEyMzQ1Ng==
ContentPaddingAddition = 32
RandomTrailers = 1
DisableCookies = 1

[Peer]
# alpha
# mimicry=rtp
PublicKey = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=
PresharedKey = MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXY=
AllowedIPs = 10.9.9.2/32

[Peer]
# beta
# expires=1900000000
# note=telefon Ivana
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
PresharedKey = Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=
AllowedIPs = 10.9.9.3/32
"""
with open(SERVER_CONF, "w") as f:
    f.write(SRV)

ALPHA_CONF = """[Interface]
PrivateKey = ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ=
Address = 10.9.9.2/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1320
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890
HeaderProtectionKey = c2VjcmV0LWtleS1mb3ItdGVzdC1vbmx5LTEyMzQ1Ng==
ContentPaddingAddition = 32
RandomTrailers = 1
DisableCookies = 1
I1 = <b 0x1111>
I2 = <b 0x2222>
I3 = <b 0x3333>

[Peer]
PublicKey = ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU=
PresharedKey = MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXY=
Endpoint = 198.51.100.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
with open(os.path.join(CLI, "alpha_awg2.conf"), "w") as f:
    f.write(ALPHA_CONF)

sys.path.insert(0, BOT_PKG)
from awgbot import core, cps  # noqa: E402

AWG_3X_KEYS = ("HeaderProtectionKey", "ContentPaddingAddition",
               "RandomTrailers", "DisableCookies")


def peer_block(name):
    text = open(SERVER_CONF).read()
    for b in re.split(r"(?=\[Peer\])", text)[1:]:
        if core._block_name(b) == name:
            return b
    return ""


def meta(name, key):
    m = re.search(rf"^#\s*{key}=(.*)$", peer_block(name), re.M)
    return m.group(1).strip() if m else ""


# ───────────────────────── 1. разбор peer-блоков ─────────────────────────
print("— разбор peer-блоков (core) —")
peers = {p.name: p for p in core.list_peers(with_runtime=False)}
chk("имя не подменено меткой mimicry", ["alpha", "beta"], sorted(peers))
chk("alpha.mimicry прочитан", "rtp", peers["alpha"].mimicry if "alpha" in peers else None)
chk("beta.mimicry пуст (старый клиент)", "", peers["beta"].mimicry if "beta" in peers else None)
chk("beta.expires цел", 1900000000, peers["beta"].expires if "beta" in peers else None)
chk("_block_name игнорирует key=value", "beta", core._block_name(peer_block("beta")))

print("— генератор CPS доступен —")
chk("cps.available()", True, cps.available())

# ───────────────────────── 2. смена профиля ─────────────────────────
print("— change_client_mimicry —")
ok, msg, path = core.change_client_mimicry("alpha", "ssdp")
chk("ssdp: ok", True, ok)
if ok:
    text = open(path).read()
    i_lines = re.findall(r"^(I[1-5])\s*=\s*(.+)$", text, re.M)
    chk("ssdp: цепочка I1-I5 (уровень 3)", ["I1", "I2", "I3", "I4", "I5"],
        [k for k, _ in i_lines])
    chk("ssdp: старые I не остались", [], [v for _, v in i_lines if v.startswith("<b 0x1111")])
    chk("ssdp: I-строки внутри [Interface]",
        True, text.index("I1 = ") < text.index("[Peer]"))
    chk("ssdp: метка обновлена", "ssdp", meta("alpha", "mimicry"))
    for k in AWG_3X_KEYS:
        chk(f"ssdp: параметр 3.x цел — {k}", True, re.search(rf"^{k}\s*=", text, re.M) is not None)
    chk("ssdp: секции целы", True, "[Interface]" in text and "[Peer]" in text)
    chk("ssdp: Endpoint цел", True, "Endpoint = 198.51.100.7:51820" in text)
    bak = [f for f in os.listdir(CLI) if f.startswith("alpha_awg2.conf.bak.")]
    chk("ssdp: бэкап создан", 1, len(bak))
else:
    print("       ", msg)

ok2, msg2, path2 = core.change_client_mimicry("alpha", "basic")
chk("basic: ok", True, ok2)
if ok2:
    text2 = open(path2).read()
    chk("basic: I-строк нет", [], re.findall(r"^I[1-5]\s*=", text2, re.M))
    chk("basic: метка none", "none", meta("alpha", "mimicry"))
    chk("basic: параметры 3.x целы", True,
        all(re.search(rf"^{k}\s*=", text2, re.M) for k in AWG_3X_KEYS))

ok3, msg3, _ = core.change_client_mimicry("alpha", "no_such_profile")
chk("неизвестный профиль отклонён", False, ok3)
ok4, msg4, _ = core.change_client_mimicry("nobody", "quic")
chk("несуществующий клиент отклонён", False, ok4)

# ───────────────────────── 3. создание клиента ─────────────────────────
print("— add_client —")
ok5, msg5, path5 = core.add_client("gamma", None, "webrtc")
chk("gamma создан", True, ok5)
if ok5:
    chk("gamma: метка записана", "webrtc", meta("gamma", "mimicry"))
    g = open(path5).read()
    chk("gamma: I1 есть", True, re.search(r"^I1\s*=", g, re.M) is not None)
    chk("gamma: параметры 3.x скопированы", True,
        all(re.search(rf"^{k}\s*=", g, re.M) for k in AWG_3X_KEYS))
    gp = {p.name: p for p in core.list_peers(with_runtime=False)}.get("gamma")
    chk("gamma: Peer.mimicry", "webrtc", gp.mimicry if gp else None)

ok6, _, _ = core.add_client("delta", None, "basic")
chk("delta (basic) создан", True, ok6)
chk("delta: метка none", "none", meta("delta", "mimicry"))

print("— I1 из серверного конфига (профиль неизвестен) —")
# Конфиги, где I1 лежит в [Interface] сервера (так делали до разделения
# серверных и клиентских параметров): бот копирует его клиенту как есть.
# Профиль такого I1 неизвестен — метку писать нельзя, иначе "none" соврёт.
srv_text = open(SERVER_CONF).read()
open(SERVER_CONF, "w").write(srv_text.replace(
    "MTU = 1320\nJc = 4", "MTU = 1320\nI1 = <b 0xdeadbeef>\nJc = 4", 1))
ok7, _, path7 = core.add_client("epsilon", None, "quic")
chk("epsilon создан", True, ok7)
chk("epsilon: I1 унаследован", "<b 0xdeadbeef>",
    (re.search(r"^I1\s*=\s*(.+)$", open(path7).read(), re.M).group(1).strip()
     if ok7 else None))
chk("epsilon: метки нет (профиль неизвестен)", "", meta("epsilon", "mimicry"))
ep = {p.name: p for p in core.list_peers(with_runtime=False)}.get("epsilon")
chk("epsilon: Peer.mimicry пуст", "", ep.mimicry if ep else None)
core.delete_client("epsilon")
srv_text = open(SERVER_CONF).read()          # читаем до открытия на запись
open(SERVER_CONF, "w").write(srv_text.replace("I1 = <b 0xdeadbeef>\n", "", 1))

# ───────────────────────── 4. метка переживает операции ─────────────────
print("— срок, заметка, переименование —")
core.set_expire("gamma", 1900000001)
chk("gamma: метка после set_expire", "webrtc", meta("gamma", "mimicry"))
chk("gamma: expires записан", "1900000001", meta("gamma", "expires"))
core.rename_client("gamma", "gamma2")
chk("gamma2: метка после rename", "webrtc", meta("gamma2", "mimicry"))
chk("gamma2: имя разобрано", True,
    "gamma2" in [p.name for p in core.list_peers(with_runtime=False)])
core.delete_client("delta")
chk("delta удалён", False, "delta" in [p.name for p in core.list_peers(with_runtime=False)])
chk("после удаления peer-блоки целы", ["alpha", "beta", "gamma2"],
    sorted(p.name for p in core.list_peers(with_runtime=False)))

# ───────────────────────── 5. bash-функции awg2.sh ─────────────────────
print("— awg2.sh: _peer_meta_get / _detect_mimicry / warp-список —")
harness = os.path.join(TMP, "harness.sh")
src = open(AWG2, encoding="utf-8", errors="replace").read()
parts = ["#!/usr/bin/env bash", "set -uo pipefail", 'warn() { echo "WARN: $*"; }']
for fn in ("_peer_meta_get", "_peer_meta_set", "_mimicry_tag",
           "_detect_mimicry", "_warp_list_awg_clients"):
    m = re.search(rf"^{fn}\(\) \{{.*?^\}}$", src, re.S | re.M)
    if not m:
        print(f"  FAIL функция {fn} не найдена в awg2.sh")
        fails += 1
        continue
    parts.append(m.group(0))
open(harness, "w").write("\n\n".join(parts) + "\n")

script = f'''
SERVER_CONF="{SERVER_CONF}"
source "{harness}"
echo "meta_alpha=$(_peer_meta_get alpha mimicry)"
echo "meta_beta=$(_peer_meta_get beta mimicry)"
echo "note_beta=$(_peer_meta_get beta note)"
echo "detect_alpha=$(_detect_mimicry "{CLI}/alpha_awg2.conf")"
echo "warp=$(_warp_list_awg_clients | tr '\\n' ';')"
'''
r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
out = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
chk("bash: _peer_meta_get alpha", "none", out.get("meta_alpha"))     # после basic
chk("bash: _peer_meta_get beta (нет метки)", "", out.get("meta_beta"))
chk("bash: _peer_meta_get beta note", "telefon Ivana", out.get("note_beta"))
chk("bash: _detect_mimicry по метке", "нет", out.get("detect_alpha"))
chk("bash: warp-список не берёт имя из шапки", True,
    out.get("warp", "").startswith("alpha|10.9.9.2;"))
if r.returncode != 0:
    print("       stderr:", r.stderr.strip()[:300])

shutil.rmtree(TMP, ignore_errors=True)
print(f"\nпроверок: {checks}, провалов: {fails}")
sys.exit(1 if fails else 0)
