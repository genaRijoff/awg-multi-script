"""
test_admins.py — список админов бота (awgbot/admins.py).

Проверяет то, что при ошибке даёт посторонним полный доступ к боту:

  • приглашение одноразовое и сгорает по TTL;
  • на диске лежит только sha256 токена, не сам токен;
  • файл admins.json пишется с правами 0600 и остаётся валидным json;
  • отзыв доступа и отзыв неиспользованных приглашений;
  • лимиты MAX_ADMINS / MAX_INVITES и валидация Telegram ID;
  • битый файл не закрывает владельцу доступ (список просто пуст).

Реальные файлы не трогаются: AWG_ADMINS_FILE уводится во временный каталог.

Запуск:  python3 tests/test_admins.py
Выход:   0 — всё сошлось, 1 — есть провалы.
"""
import hashlib
import importlib
import json
import os
import stat
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "awg_bot")))

TMP = tempfile.mkdtemp(prefix="awg-admins-test-")
os.environ["AWG_ADMINS_FILE"] = os.path.join(TMP, "admins.json")

from awgbot import admins  # noqa: E402  (после подмены пути и env)

FAIL = 0


def check(cond, label, extra=""):
    global FAIL
    if cond:
        print("  OK   %s" % label)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (label, extra))


def reset():
    try:
        os.unlink(admins.ADMINS_FILE)
    except FileNotFoundError:
        pass


print("── пустое состояние ──")
reset()
check(admins.invited_ids() == set(), "нет файла — список пуст")
check(admins.pending_invites() == 0, "нет файла — приглашений нет")

print("\n── добавление вручную ──")
ok, msg = admins.add(555001, added_by=111, username="alice")
check(ok, "add() принял админа", msg)
check(admins.invited_ids() == {555001}, "админ в списке")
ok, msg = admins.add(555001, added_by=111)
check(not ok, "повторный add() отклонён", msg)
entry = admins.list_invited()[0]
check(entry.username == "alice" and entry.added_by == 111 and entry.added_at > 0,
      "сохранены username/кто добавил/когда")

print("\n── права и формат файла ──")
mode = stat.S_IMODE(os.stat(admins.ADMINS_FILE).st_mode)
check(mode == 0o600, "admins.json имеет права 0600", oct(mode))
raw = json.loads(open(admins.ADMINS_FILE).read())
check(isinstance(raw.get("admins"), dict) and "555001" in raw["admins"],
      "файл — валидный json ожидаемой структуры")
check(not [f for f in os.listdir(TMP) if f.endswith(".tmp")],
      "временные файлы атомарной записи убраны")

print("\n── валидация ID ──")
for bad in (0, -1, 1 << 60, "123"):
    ok, _ = admins.add(bad, added_by=111)
    check(not ok, "add(%r) отклонён" % (bad,))

print("\n── отзыв доступа ──")
ok, msg = admins.remove(555001, removed_by=111)
check(ok and admins.invited_ids() == set(), "remove() отозвал доступ", msg)
ok, _ = admins.remove(555001, removed_by=111)
check(not ok, "повторный remove() отклонён")

print("\n── приглашение: одноразовость ──")
reset()
token, exp = admins.create_invite(created_by=111)
check(isinstance(token, str) and len(token) >= 20, "токен выдан", str(token))
check(admins.pending_invites() == 1, "приглашение числится живым")
stored = json.loads(open(admins.ADMINS_FILE).read())["invites"]
check(token not in json.dumps(stored), "сам токен на диск не попал")
check(hashlib.sha256(token.encode()).hexdigest() in stored,
      "на диске лежит sha256 токена")

ok, msg = admins.consume_invite(token, 555002, "bob")
check(ok and 555002 in admins.invited_ids(), "первая активация выдала доступ", msg)
ok, msg = admins.consume_invite(token, 555003, "eve")
check(not ok and 555003 not in admins.invited_ids(),
      "повторная активация той же ссылки отклонена", msg)
check(admins.pending_invites() == 0, "использованное приглашение погашено")
check(admins.list_invited()[0].added_by == 111, "запомнили, кто пригласил")

ok, _ = admins.consume_invite("совершенно-левый-токен", 555004)
check(not ok and 555004 not in admins.invited_ids(), "чужой токен отклонён")
ok, _ = admins.consume_invite("x" * 200, 555005)
check(not ok, "переросший токен отклонён без падения")

print("\n── приглашение: срок жизни ──")
reset()
token, _ = admins.create_invite(created_by=111)
data = json.loads(open(admins.ADMINS_FILE).read())
key = next(iter(data["invites"]))
data["invites"][key]["exp"] = 1  # 1970 — заведомо просрочено
with open(admins.ADMINS_FILE, "w") as f:
    json.dump(data, f)
ok, _ = admins.consume_invite(token, 555006)
check(not ok and 555006 not in admins.invited_ids(), "просроченная ссылка не работает")
check(admins.pending_invites() == 0, "просроченное приглашение вычищено")

print("\n── отзыв приглашений ──")
reset()
admins.create_invite(created_by=111)
t2, _ = admins.create_invite(created_by=111)
check(admins.pending_invites() == 2, "живут два приглашения")
check(admins.revoke_invites() == 2, "revoke_invites() погасил оба")
ok, _ = admins.consume_invite(t2, 555007)
check(not ok, "отозванная ссылка не работает")

print("\n── лимиты ──")
reset()
for i in range(admins.MAX_ADMINS):
    admins.add(600000 + i, added_by=111)
ok, msg = admins.add(699999, added_by=111)
check(not ok and 699999 not in admins.invited_ids(),
      "MAX_ADMINS=%d соблюдён" % admins.MAX_ADMINS, msg)
reset()
for _ in range(admins.MAX_INVITES):
    admins.create_invite(created_by=111)
token, msg = admins.create_invite(created_by=111)
check(token is None, "MAX_INVITES=%d соблюдён" % admins.MAX_INVITES, str(msg))

print("\n── битый файл ──")
with open(admins.ADMINS_FILE, "w") as f:
    f.write("{ это не json")
check(admins.invited_ids() == set(), "битый файл — пустой список, без исключения")
ok, _ = admins.add(555008, added_by=111)
check(ok and admins.invited_ids() == {555008}, "битый файл перезаписан корректным")

print("\n── deep-link payload ──")
reset()
token, _ = admins.create_invite(created_by=111)
payload = admins.INVITE_PREFIX + token
check(len(payload) <= 64, "payload влезает в лимит Telegram (64)", str(len(payload)))
check(all(c.isalnum() or c in "_-" for c in payload),
      "payload — только допустимые для deep-link символы")

reset()
os.rmdir(TMP) if not os.listdir(TMP) else None
print("\nпровалов:", FAIL)
sys.exit(1 if FAIL else 0)
