"""
test_bot_access.py — проверка доступа к боту на живом диспетчере aiogram.

Обновления прогоняются через настоящий Dispatcher с настоящими роутерами и
middleware; наружу вместо сети подставлена сессия-заглушка, которая
записывает вызовы Bot API. То есть проверяется ровно то, что увидит Telegram.

Зачем: доступ раздаёт один внешний слой (AccessMiddleware) вместо проверки в
каждом из 70+ обработчиков. Выигрыш в том, что забыть проверку в новой кнопке
теперь нельзя, но цена — если слой навесить не на тот роутер, дыра открывается
сразу везде. Этот тест и держит слой на месте.

Запуск:  python3 tests/test_bot_access.py
Выход:   0 — всё сошлось, 1 — есть провалы, 0 с пометкой «пропущен» — если
         aiogram не установлен (тогда проверять нечего).
"""
import asyncio
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "awg_bot"))

try:
    from aiogram.client.session.base import BaseSession
    from aiogram.methods import TelegramMethod
    from aiogram.types import CallbackQuery, Chat, Message, Update, User
except ImportError as exc:                      # aiogram ставится в venv бота
    print("пропущен: не установлен aiogram (%s)" % exc)
    sys.exit(0)

OWNER = 111111111
STRANGER = 222222222
INVITED = 333333333

os.environ.setdefault("BOT_TOKEN", "42:TEST")
os.environ.setdefault("ADMIN_ID", str(OWNER))
# Настоящий /etc/awg-bot.conf брать нельзя: там боевой токен и чужой ADMIN_ID.
os.environ["AWG_BOT_CONF"] = os.path.join(_HERE, "_no_such_conf")
# Список приглашённых админов и состояние мониторинга не должны утекать из
# рабочих каталогов машины, на которой гоняют тест.
os.environ.setdefault("AWG_ADMINS_FILE", os.path.join(_HERE, "_admins_test.json"))
os.environ.setdefault("AWG_MON_STATE", os.path.join(_HERE, "_monitor_test.json"))

from awgbot import bot as botmod                # noqa: E402  (после env)


class MockSession(BaseSession):
    """Сессия без сети: запоминает вызовы и отдаёт правдоподобный результат."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, dict]] = []

    async def close(self) -> None:
        pass

    async def make_request(self, bot, method: TelegramMethod, timeout=None):
        name = type(method).__name__
        self.calls.append((name, method.model_dump(exclude_none=True)))
        if name == "AnswerCallbackQuery":
            return True
        if name in ("SendMessage", "EditMessageText"):
            return _make_message(1, OWNER, "ok")
        return True

    async def stream_content(self, url, headers=None, timeout=30,
                             chunk_size=65536, raise_for_status=True):
        yield b""


def _make_message(message_id: int, uid: int, text: str) -> Message:
    user = User(id=uid, is_bot=False, first_name="T")
    chat = Chat(id=uid, type="private")
    return Message(message_id=message_id, date=datetime.now(timezone.utc),
                   chat=chat, from_user=user, text=text).as_(botmod.bot)


def _callback_update(uid: int, data: str, update_id: int = 1) -> Update:
    user = User(id=uid, is_bot=False, first_name="T")
    cq = CallbackQuery(id="cb%d" % update_id, from_user=user, chat_instance="ci",
                       data=data, message=_make_message(10, uid, "меню"))
    return Update(update_id=update_id, callback_query=cq)


def _message_update(uid: int, text: str, update_id: int = 1) -> Update:
    return Update(update_id=update_id, message=_make_message(11, uid, text))


fail = 0


def chk(name: str, cond: bool, detail: str = "") -> None:
    global fail
    if cond:
        print("  OK   %s" % name)
    else:
        fail += 1
        print("  FAIL %s%s" % (name, (" — " + detail) if detail else ""))


async def feed(update: Update) -> list[tuple[str, dict]]:
    """Прогоняет обновление и возвращает вызовы Bot API, которые оно породило."""
    session: MockSession = botmod.bot.session          # type: ignore[assignment]
    session.calls.clear()
    await botmod.dp.feed_update(botmod.bot, update)
    return list(session.calls)


def denied(calls: list[tuple[str, dict]]) -> bool:
    return any(name == "AnswerCallbackQuery" and "Доступ запрещён" in str(payload.get("text", ""))
               for name, payload in calls)


async def main() -> int:
    botmod.bot.session = MockSession()

    print("── посторонний ──")
    calls = await feed(_callback_update(STRANGER, "status", 1))
    chk("кнопка постороннего отбита", denied(calls), str(calls)[:120])
    chk("постороннему ничего не показали",
        not any(n in ("EditMessageText", "SendMessage") for n, _ in calls), str(calls)[:120])

    calls = await feed(_message_update(STRANGER, "привет", 2))
    chk("на постороннее сообщение бот молчит", calls == [], str(calls)[:120])

    print("── владелец ──")
    calls = await feed(_callback_update(OWNER, "not_installed", 3))
    chk("кнопка владельца обработана",
        any(n == "AnswerCallbackQuery" for n, _ in calls) and not denied(calls),
        str(calls)[:120])

    calls = await feed(_callback_update(OWNER, "noop", 4))
    chk("noop не считается отказом", not denied(calls), str(calls)[:120])

    print("── приглашённый админ против владельца ──")
    # Приглашённый управляет клиентами, но не списком админов. Флаг владельца
    # теперь приходит из middleware — проверяем, что он приходит правильный.
    ok, _ = botmod.admins.add(INVITED, added_by=OWNER)
    chk("приглашённый добавлен", ok)
    calls = await feed(_callback_update(INVITED, "admins", 6))
    answers = " ".join(str(p.get("text", "")) for n, p in calls if n == "AnswerCallbackQuery")
    chk("приглашённому закрыто управление админами", "владельцу" in answers, answers[:120])
    chk("экран админов ему не показан",
        not any(n == "EditMessageText" for n, _ in calls), str(calls)[:120])

    calls = await feed(_callback_update(OWNER, "admins", 7))
    chk("владельцу управление админами открыто",
        any(n == "EditMessageText" for n, _ in calls), str(calls)[:160])

    print("── /start ──")
    # /start живёт в публичном роутере: через него приходят приглашения.
    calls = await feed(_message_update(STRANGER, "/start", 5))
    sent = " ".join(str(p.get("text", "")) for n, p in calls if n == "SendMessage")
    chk("постороннему /start отвечает подсказкой с его ID", str(STRANGER) in sent,
        sent[:160])

    print("── структура ──")
    names = [r.name for r in botmod.dp.sub_routers]
    chk("роутеры подключены в правильном порядке", names == ["start", "main"], str(names))
    chk("слой доступа стоит на сообщениях основного роутера",
        any(isinstance(m, botmod.AccessMiddleware)
            for m in botmod.router.message.outer_middleware),
        "нет AccessMiddleware")
    chk("слой доступа стоит на кнопках основного роутера",
        any(isinstance(m, botmod.AccessMiddleware)
            for m in botmod.router.callback_query.outer_middleware),
        "нет AccessMiddleware")
    chk("публичный роутер без слоя доступа (иначе приглашения не работают)",
        not any(isinstance(m, botmod.AccessMiddleware)
                for m in botmod.start_router.message.outer_middleware))
    # Проверка доступа больше не должна дублироваться в обработчиках: две
    # независимые копии логики доступа разъезжаются.
    src = open(os.path.join(_HERE, "..", "awg_bot", "awgbot", "bot.py"),
               encoding="utf-8").read()
    chk("в обработчиках не осталось ручных проверок authorized()",
        "return await deny(cq)" not in src and "return await deny(msg)" not in src)

    print("\nпровалов:", fail)
    return 1 if fail else 0


if __name__ == "__main__":
    try:
        code = asyncio.run(main())
    finally:
        for tmp in ("_admins_test.json", "_monitor_test.json"):
            path = os.path.join(_HERE, tmp)
            if os.path.exists(path):
                os.unlink(path)
    sys.exit(code)
