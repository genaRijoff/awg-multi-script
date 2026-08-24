"""
test_channel.py — канал обновлений бота (stable / beta).

Канал читают две независимые реализации: bash (`awg_bot/awg-bot`, функция
channel_read) и python (`awgbot/core.update_channel`). Разъедутся — бот будет
показывать один канал, а обновляться из другого. Тест гоняет обе на одних и
тех же конфигах и сверяет ответы, а заодно проверяет:

  • приоритет UPDATE_CHANNEL → REPO_URL → канал awg2 → stable;
  • нормализацию адресов репозитория (.git, слэш, регистр, git@);
  • channel_set: пишет и UPDATE_CHANNEL, и REPO_URL, не трогая токен;
  • определение «чужого» REPO_URL (форк), который переключение перезапишет.

Ни /etc/awg-bot.conf, ни /var/lib/awg2 не трогаются — всё во временном каталоге.

Запуск:  python3 tests/test_channel.py
Выход:   0 — всё сошлось, 1 — есть провалы.
"""
import os
import re
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
BOT_PKG = os.path.abspath(os.path.join(_HERE, "..", "awg_bot"))
AWG_BOT = os.path.join(BOT_PKG, "awg-bot")
sys.path.insert(0, BOT_PKG)

TMP = tempfile.mkdtemp(prefix="awg-channel-test-")
CONF = os.path.join(TMP, "awg-bot.conf")
AWG2_CH = os.path.join(TMP, "awg2-channel")

STABLE = "https://github.com/pumbaX/awg-multi-script"
BETA = "https://github.com/genaRijoff/awg-multi-script"

FAIL = 0


def check(cond, label, extra=""):
    global FAIL
    if cond:
        print("  OK   %s" % label)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (label, extra))


# ── харнес: вырезаем функции канала из awg-bot и зовём их в чистом bash ──
src = open(AWG_BOT, encoding="utf-8", errors="replace").read()
parts = [
    "#!/usr/bin/env bash", "set -uo pipefail",
    'ok() { :; }', 'err() { echo "ERR: $*" >&2; }',
    'warn() { echo "WARN: $*" >&2; }', 'info() { :; }', "D=''; N=''; Y=''",
    f'CONF="{CONF}"', f'AWG2_CHANNEL_FILE="{AWG2_CH}"',
    f'UPDATE_REPO_STABLE="{STABLE}"', f'UPDATE_REPO_BETA="{BETA}"',
    'get_local_src() { grep -m1 "^LOCAL_SRC=" "$CONF" 2>/dev/null | cut -d= -f2- || true; }',
]
for fn in ("norm_repo", "channel_repo", "channel_label", "channel_read",
           "channel_repo_is_custom", "channel_set"):
    m = re.search(rf"^{fn}\(\) \{{.*?^\}}$", src, re.S | re.M)
    if not m:
        print(f"  FAIL функция {fn} не найдена в awg-bot")
        FAIL += 1
        continue
    parts.append(m.group(0))
HARNESS = os.path.join(TMP, "harness.sh")
open(HARNESS, "w").write("\n\n".join(parts) + "\n")


def bash(snippet: str) -> str:
    r = subprocess.run(["bash", "-c", f'source "{HARNESS}"\n{snippet}'],
                       capture_output=True, text=True)
    return r.stdout.strip()


def py_channel() -> str:
    """core.update_channel() на том же конфиге — в отдельном процессе."""
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from awgbot import core\n"
        "core.BOT_CONF_PATH = %r\n"
        "core.AWG2_CHANNEL_FILE = %r\n"
        "print(core.update_channel())\n" % (BOT_PKG, CONF, AWG2_CH)
    )
    env = dict(os.environ)
    env.pop("REPO_URL", None)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    return r.stdout.strip() or r.stderr.strip()


def write_conf(*lines):
    with open(CONF, "w") as f:
        f.write("BOT_TOKEN=123456:secret\nADMIN_ID=111\n" + "".join(l + "\n" for l in lines))


def both(label, expect):
    """Обе реализации должны дать один и тот же канал."""
    b, p = bash("channel_read"), py_channel()
    check(b == expect and p == expect, label, f"bash={b!r} python={p!r}")


print("── приоритет источников ──")
write_conf()
both("пустой конфиг, нет канала awg2 → stable", "stable")

open(AWG2_CH, "w").write("beta\n")
both("канал awg2 = beta наследуется ботом", "beta")

write_conf(f"REPO_URL={BETA}")
both("REPO_URL на бета-репозиторий → beta", "beta")

write_conf(f"REPO_URL={STABLE}")
both("REPO_URL на стабильный → stable (канал awg2 не перебивает)", "stable")

write_conf(f"UPDATE_CHANNEL=stable", f"REPO_URL={BETA}")
both("явный UPDATE_CHANNEL сильнее REPO_URL", "stable")

write_conf("UPDATE_CHANNEL=мусор")
both("битый канал в конфиге → падаем на канал awg2", "beta")

os.unlink(AWG2_CH)
write_conf("UPDATE_CHANNEL=мусор")
both("битый канал и нет канала awg2 → stable", "stable")

print("\n── нормализация адресов ──")
for url, expect in ((BETA + ".git", "beta"), (BETA + "/", "beta"),
                    (BETA.upper().replace("HTTPS://GITHUB.COM", "https://github.com"), "beta"),
                    ("git@github.com:genaRijoff/awg-multi-script.git", "beta"),
                    ("https://github.com/someone/fork", "stable")):
    write_conf(f"REPO_URL={url}")
    b, p = bash("channel_read"), py_channel()
    check(b == expect and p == expect, f"{url} → {expect}", f"bash={b!r} python={p!r}")

print("\n── channel_set ──")
write_conf()
out = bash("channel_set beta >/dev/null; grep -c . " + CONF)
conf_text = open(CONF).read()
check("UPDATE_CHANNEL=beta" in conf_text, "channel_set записал UPDATE_CHANNEL")
check(f"REPO_URL={BETA}" in conf_text, "channel_set записал REPO_URL канала")
check("BOT_TOKEN=123456:secret" in conf_text and "ADMIN_ID=111" in conf_text,
      "токен и админы не тронуты")
check(oct(os.stat(CONF).st_mode)[-3:] == "600", "конфиг остался 0600",
      oct(os.stat(CONF).st_mode))
both("после channel_set обе реализации видят beta", "beta")

bash("channel_set stable >/dev/null")
conf_text = open(CONF).read()
check(conf_text.count("UPDATE_CHANNEL=") == 1 and conf_text.count("REPO_URL=") == 1,
      "повторное переключение не плодит дубли строк")
both("возврат на стабильный канал", "stable")

check("ERR" in subprocess.run(
    ["bash", "-c", f'source "{HARNESS}"; channel_set nightly'],
    capture_output=True, text=True).stderr, "неизвестный канал отклонён")

print("\n── чужой REPO_URL (форк) ──")
write_conf("REPO_URL=https://github.com/someone/fork")
check(subprocess.run(["bash", "-c", f'source "{HARNESS}"; channel_repo_is_custom'],
                     capture_output=True).returncode == 0, "форк опознан как чужой адрес")
write_conf(f"REPO_URL={STABLE}")
check(subprocess.run(["bash", "-c", f'source "{HARNESS}"; channel_repo_is_custom'],
                     capture_output=True).returncode == 1, "адрес канала чужим не считается")

print("\n── ярлыки и репозитории ──")
check(bash("channel_repo beta") == BETA, "channel_repo beta")
check(bash("channel_repo stable") == STABLE, "channel_repo stable")
check(bash("channel_repo") == STABLE, "channel_repo без аргумента → stable")
check(bash("channel_label beta") == "бета" and bash("channel_label stable") == "стабильный",
      "человекочитаемые ярлыки канала")

print("\nпровалов:", FAIL)
sys.exit(1 if FAIL else 0)
