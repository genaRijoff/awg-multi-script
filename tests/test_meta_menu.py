"""
test_meta_menu.py — меню «Клиенты» и «Сроки, лимиты и скорость» с нечисловыми
метками срока и скорости в awg0.conf (правка руками, бэкап с другого сервера):
меню не падает, метка показана как повреждённая, остальные клиенты на месте;
числовые метки — как раньше.

Запуск:  python3 tests/test_meta_menu.py [путь/к/awg2.sh]
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sandbox import *  # noqa: E402,F401,F403

CONF = os.path.join(ROOT, "etc/amnezia/amneziawg/awg0.conf")
BASE = OLD20.replace("# expires=1\n", "")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def setup(lines):
    """Метки alice (первой в списке): после неё в меню должен остаться bob."""
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    with open(CONF, "w", encoding="utf-8") as f:
        f.write(BASE.replace("# alice\n", "# alice\n" + "".join(f"# {ln}\n" for ln in lines), 1))
    with open(LINKS, "w") as f:
        f.write("awg0\n")


def menus():
    rc1, o1, e1 = bash("do_list_clients")
    rc2, o2, e2 = bash("do_expire_menu </dev/null")
    global LIST, EXPM
    LIST, EXPM = ANSI.sub("", o1), ANSI.sub("", o2)
    return rc1, rc2, LIST + EXPM, e1 + e2


def alice_block(text):
    """Строки меню от alice до следующего клиента."""
    m = re.search(r"alice.*?(?=\bbob\b)", text, re.S)
    return m.group(0) if m else ""


BROKE = re.compile(r"unbound variable|syntax error|invalid arithmetic|value too great|ошибка в выражении", re.I)

print(f"Python {sys.version.split()[0]}")
print("\nЧисловые метки — как раньше")
future = int(time.time()) + 3 * 86400
for lines, want, label in (
    ([f"expires={future}"], r"срок: \d\d\.\d\d\.\d{4} \d\d:\d\d \(через", "срок в будущем"),
    ([f"expires= {future}"], r"срок: \d\d\.\d\d\.\d{4} \d\d:\d\d \(через", "срок с пробелом перед числом"),
    (["speed=5"], r"скорость: 5 Мбит/с", "своя скорость"),
    (["speed=5", "limit_slow=2", "slowed_by=traffic"], r"скорость: 🐢 2 Мбит/с — лимит исчерпан", "замедлен ниже своей"),
    (["speed=1", "limit_slow=2", "slowed_by=traffic"], r"скорость: 1 Мбит/с", "своя скорость ниже замедления"),
):
    setup(lines)
    rc1, rc2, out, err = menus()
    chk(f"{label}: меню показывает как раньше", rc1 == 0 and rc2 == 0 and re.search(want, alice_block(out))
        and not BROKE.search(err), [rc1, rc2, alice_block(out)[-300:], err[-300:]])

print("\nНечисловые метки — «повреждена», меню не обрывается")
for key, val, extra in (("expires", "abc", []), ("expires", "²", []), ("expires", "-1", []), ("expires", "1.5", []),
                        ("speed", "abc", ["limit_slow=2", "slowed_by=traffic"]), ("speed", "²", []),
                        ("limit_slow", "abc", ["speed=5", "slowed_by=traffic"])):
    setup([f"{key}={val}"] + extra)
    rc1, rc2, out, err = menus()
    blk = alice_block(out)
    want = "скорость: 5 Мбит/с" if key == "limit_slow" else "повреждена"
    chk(f"M.1 alice: {key}={ascii(val)} — без ошибок вычисления, в меню «{want}»",
        rc1 == 0 and rc2 == 0 and want in blk and not BROKE.search(err), [blk[-300:], err[-300:]])
    chk(f"M.2 alice: {key}={ascii(val)} — в «Клиентах» после alice есть bob, меню сроков показано до конца",
        ") bob " in LIST.split("alice", 1)[-1] and "Назад" in EXPM, [LIST[-200:], EXPM[-200:]])

summary()
