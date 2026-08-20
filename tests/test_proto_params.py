"""
test_proto_params.py — сквозная совместимость AWG 2.0 / 3.0 / 3.1.

Параметры 3.x — уровня устройства: они обязаны совпадать на обоих концах,
иначе клиент к серверу не подключится. Поэтому набор, который awg2 кладёт в
конфиг сервера, обязан целиком доезжать до клиента — и когда клиента создаёт
сам скрипт, и когда его выдаёт бот. Скрипт и бот отбирают эти строки по
двум независимым спискам (AWG_PARAM_KEYS_RE в awg2.sh и перечисление в
core.add_client), и рассинхрон этих списков — тихий баг: клиент получит
конфиг 2.0 и молча не поднимется.

Тест берёт настоящий генератор gen_awg3_params из awg2.sh, а не его копию.

Запуск:  python3 tests/test_proto_params.py [путь/к/awg2.sh]
Выход:   0 — версии согласованы, 1 — есть провалы.
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


SRC = open(AWG2, encoding="utf-8", errors="replace").read()

# ── окружение: заглушка awg (нужна gen_awg3_params для genkey) ──
TMP = tempfile.mkdtemp(prefix="awg-proto-test.")
BIN, ETC, CLI = (os.path.join(TMP, d) for d in ("bin", "etc", "clients"))
for d in (BIN, ETC, CLI):
    os.makedirs(d)
SERVER_CONF = os.path.join(ETC, "awg0.conf")
with open(os.path.join(BIN, "awg"), "w") as f:
    f.write("#!/usr/bin/env bash\n"
            "case \"$1\" in\n"
            "  genkey|genpsk) head -c 32 /dev/urandom | base64 ;;\n"
            "  pubkey)        head -c 32 /dev/urandom | base64 ;;\n"
            "  show)          exit 1 ;;\n"
            "  *)             exit 0 ;;\n"
            "esac\n")
os.chmod(os.path.join(BIN, "awg"), 0o755)
with open(os.path.join(BIN, "awg-quick"), "w") as f:
    f.write("#!/usr/bin/env bash\nexit 0\n")
os.chmod(os.path.join(BIN, "awg-quick"), 0o755)
shutil.copy2(AWG2, os.path.join(BIN, "awg2"))

os.environ["PATH"] = BIN + os.pathsep + os.environ.get("PATH", "")
os.environ["AWG_SERVER_CONF"] = SERVER_CONF
os.environ["AWG_CLIENT_DIR"] = CLI
os.environ["AWG_BOT_CONF"] = os.path.join(ETC, "awg-bot.conf")
os.environ["AWG_NOTES_FILE"] = os.path.join(ETC, "notes.json")

sys.path.insert(0, BOT_PKG)
from awgbot import core  # noqa: E402


def bash_fn(name):
    m = re.search(rf"^{name}\(\) \{{.*?^\}}$", SRC, re.S | re.M)
    if not m:
        raise SystemExit(f"функция {name} не найдена в awg2.sh")
    return m.group(0)


def gen3(proto):
    """Настоящий gen_awg3_params из awg2.sh для указанной версии."""
    script = "\n\n".join([
        "set -uo pipefail",
        'log_err() { :; }',
        bash_fn("rand_range"),
        bash_fn("gen_awg3_params"),
        f'AWG_PROTO="{proto}"',
        "gen_awg3_params",
    ])
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"gen_awg3_params({proto}) упал: {r.stderr.strip()[:200]}")
    return r.stdout.strip()


# Базовые параметры 2.0 — в awg2 они собираются в AWG_PARAMS_LINES.
BASE_20 = ["Jc = 4", "Jmin = 40", "Jmax = 70",
           "S1 = 0", "S2 = 0", "S3 = 0", "S4 = 0",
           "H1 = 1234567", "H2 = 2345678", "H3 = 3456789", "H4 = 4567890"]

PARAMS = {
    "2.0": BASE_20,
    "3.0": BASE_20 + gen3("3.0").splitlines(),
    "3.1": BASE_20 + gen3("3.1").splitlines(),
}

print("— генератор параметров awg2.sh —")
keys = {v: [l.split("=")[0].strip() for l in lines] for v, lines in PARAMS.items()}
chk("3.1 добавляет RandomTrailers", True, "RandomTrailers" in keys["3.1"])
chk("3.1 добавляет DisableCookies", True, "DisableCookies" in keys["3.1"])
chk("3.0 без параметров 3.1", [], [k for k in ("RandomTrailers", "DisableCookies")
                                   if k in keys["3.0"]])
chk("3.0 даёт защиту заголовков", True, "HeaderProtectionKey" in keys["3.0"])
chk("2.0 без параметров 3.x", [], [k for k in keys["2.0"]
                                   if k not in {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                                                "H1", "H2", "H3", "H4"}])
# Инвариант из комментария в awg2.sh: сессия не должна отвергаться раньше рекея
for v in ("3.0", "3.1"):
    d = dict(l.split(" = ", 1) for l in PARAMS[v] if " = " in l)
    rat_hi = int(d["RekeyAfterTime"].split("-")[-1])
    rjt_lo = int(d["RejectAfterTime"].split("-")[0])
    chk(f"{v}: RejectAfterTime > RekeyAfterTime", True, rjt_lo > rat_hi)

# ── отбор строк регуляркой awg2.sh ──
m = re.search(r'^AWG_PARAM_KEYS_RE="\((.+)\)"\s*$', SRC, re.M)
if not m:
    raise SystemExit("AWG_PARAM_KEYS_RE не найдена в awg2.sh")
SH_RE = re.compile(rf"^({m.group(1)}) = ")

# ── список ключей бота из core.add_client ──
src_core = open(os.path.join(BOT_PKG, "awgbot", "core.py")).read()
mc = re.search(r'for key in \((.*?)\):', src_core, re.S)
if not mc:
    raise SystemExit("список ключей не найден в core.add_client")
BOT_KEYS = set(re.findall(r'"([^"]+)"', mc.group(1)))

print("— скрипт и бот отбирают одни и те же строки —")
for v, lines in PARAMS.items():
    picked_sh = [l for l in lines if SH_RE.match(l)]
    picked_bot = [l for l in lines if l.split(" = ")[0] in BOT_KEYS]
    chk(f"{v}: awg2.sh переносит все параметры", lines, picked_sh)
    chk(f"{v}: бот переносит все параметры", lines, picked_bot)

print("— бот выдаёт клиента для каждой версии —")
SRV_HEAD = """# AWG_PROFILE=pro
# AmneziaWG Toolza — AWG {v} server config
# Region: world
# AWG_PROTO={v}
# AWG_OBF_LEVEL=3
# AWG_MIMICRY=quic
[Interface]
PrivateKey = 4FZoPwYBIkc4ZP5+2vX6c1J5C1p1s3vDqk8UlG2xVFo=
Address = 10.9.9.1/24
ListenPort = 51820
MTU = 1320
{params}

[Peer]
# seed
# mimicry=quic
PublicKey = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=
PresharedKey = MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXY=
AllowedIPs = 10.9.9.2/32
"""
for v, lines in PARAMS.items():
    open(SERVER_CONF, "w").write(SRV_HEAD.format(v=v, params="\n".join(lines)))
    # клиент-донор уровня 3, чтобы бот выдавал полную цепочку I1-I5
    open(os.path.join(CLI, "seed_awg2.conf"), "w").write(
        "[Interface]\nI1 = <b 0x11>\nI2 = <b 0x22>\n[Peer]\n")
    name = "cli" + v.replace(".", "")
    ok, msg, path = core.add_client(name, None, "quic")
    chk(f"{v}: клиент создан ботом", True, ok)
    if not ok:
        print("       ", msg)
        continue
    text = open(path).read()
    missing = [l for l in lines if l not in text]
    chk(f"{v}: все awg-параметры в конфиге клиента", [], missing)
    chk(f"{v}: цепочка I1-I5 выдана", ["I1", "I2", "I3", "I4", "I5"],
        re.findall(r"^(I[1-5]) = ", text, re.M))
    chk(f"{v}: Endpoint есть", True, bool(re.search(r"^Endpoint = \S+:51820$", text, re.M)))
    # На 3.x keepalive обязан быть диапазоном: фиксированные 25 с дают ровную
    # временную сигнатуру — то самое, что 3.x и призван скрывать.
    ka = re.search(r"^PersistentKeepalive = (.+)$", text, re.M)
    chk(f"{v}: PersistentKeepalive по версии",
        True, bool(re.fullmatch(r"\d+" if v == "2.0" else r"\d+-\d+", ka.group(1).strip()))
        if ka else False)
    chk(f"{v}: метка профиля", "quic",
        (re.search(r"^#\s*mimicry=(\S+)", "".join(
            b for b in re.split(r"(?=\[Peer\])", open(SERVER_CONF).read())[1:]
            if core._block_name(b) == name), re.M) or [None, ""])[1])
    # смена мимикрии не должна ронять параметры версии
    ok2, msg2, path2 = core.change_client_mimicry(name, "dns")
    chk(f"{v}: смена мимикрии прошла", True, ok2)
    if ok2:
        t2 = open(path2).read()
        chk(f"{v}: параметры целы после смены", [], [l for l in lines if l not in t2])
    os.unlink(os.path.join(CLI, "seed_awg2.conf"))

shutil.rmtree(TMP, ignore_errors=True)
print(f"\nпроверок: {checks}, провалов: {fails}")
sys.exit(1 if fails else 0)
