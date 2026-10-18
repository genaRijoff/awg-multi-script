"""jobs.py — долгие операции awg2 с живым журналом.

Задача запускается в awg2 (awg2 api job start) и живёт в своём юните
systemd, а бот лишь следит за ней: в том же экране показывает последние
строки журнала, в конце — итог с кнопкой «Назад». Незавершённые задачи
пишутся в jobs.json: если бот перезапустили посреди задачи (или задача
сама его обновляла), после старта он дочитает журнал и поставит итог в то
же сообщение.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest, TelegramNetworkError, TelegramRetryAfter
from aiogram.types import InlineKeyboardMarkup

from . import api, progress, store, ui

log = logging.getLogger("awgbot.jobs")

POLL = 2.0          # опрос awg2
EDIT_EVERY = 4.0    # правка сообщения не чаще — лимиты Telegram
LOG_LINES = 25
LOG_KEEP = 20000    # сколько журнала держать в памяти

# Действие после успешной задачи: (bot, chat_id, итог задачи).
Done = Callable[[Bot, int, dict[str, Any]], Awaitable[None]]

_tasks: set[asyncio.Task] = set()


def _spawn(coro: Awaitable[None]) -> None:
    task = asyncio.ensure_future(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def _tail(text: str, n: int = LOG_LINES) -> str:
    return "\n".join(text.strip("\n").splitlines()[-n:])


async def start(target: ui.Target, title: str, *args: Any, stdin: str | bytes | None = None,
                back_to: str = "main", done: Done | None = None,
                ok_buttons: list[ui.Button] | None = None) -> None:
    """Запускает задачу и сразу возвращается; журнал обновляется в фоне.
    ok_buttons — кнопки итога при успехе (над «Назад»)."""
    r = await api.job_start(*args, stdin=stdin)
    if not r.ok or not isinstance(r.data, dict):
        await ui.render(target, ui.fail(r, title), ui.kb(ui.back(back_to)))
        return
    job_id = r.data["id"]
    text = f"⏳ <b>{ui.esc(title)}</b>\n<i>запускаю…</i>"
    msg = await ui.render(target, text)
    if msg is None:
        chat = ui.chat_of(target)
        msg = await ui.show_new(chat.bot, chat.chat.id, text)  # type: ignore[arg-type]
    ui.busy.add((msg.chat.id, msg.message_id))
    ok_buttons = [list(b) for b in ok_buttons or []]
    bar = progress.kind(args)
    store.job_add(job_id, {"chat": msg.chat.id, "msg": msg.message_id, "title": title,
                           "back": back_to, "started": int(time.time()), "ok_buttons": ok_buttons, "bar": bar})
    _spawn(_follow(msg.bot, job_id, msg.chat.id, msg.message_id, title, back_to, done,
                   ok_buttons=ok_buttons, bar=bar))


def resume(bot: Bot) -> int:
    """Доследить задачи, начатые до перезапуска бота."""
    pending = store.jobs()
    for job_id, info in pending.items():
        try:
            _spawn(_follow(bot, job_id, int(info["chat"]), int(info["msg"]),
                           str(info.get("title") or "Задача"), str(info.get("back") or "main"), None,
                           int(info.get("started") or time.time()), info.get("ok_buttons") or [],
                           str(info.get("bar") or "")))
        except (KeyError, TypeError, ValueError):
            store.job_done(job_id)
    return len(pending)


async def _edit(bot: Bot, chat_id: int, msg_id: int, text: str,
                markup: InlineKeyboardMarkup | None = None) -> bool:
    """Правка сообщения задачи. False — сообщения больше нет."""
    for _ in range(3):
        try:
            await bot.edit_message_text(ui.fit(ui.clip(text), markup), chat_id=chat_id, message_id=msg_id,
                                        reply_markup=markup, disable_web_page_preview=True)
            return True
        except TelegramRetryAfter as e:
            await asyncio.sleep(min(int(e.retry_after) + 1, 30))
        except TelegramNetworkError as e:
            log.debug("правка сообщения задачи, сеть: %s", e)
            await asyncio.sleep(2)
        except TelegramBadRequest as e:
            if "not modified" in str(e):
                return True
            log.debug("правка сообщения задачи: %s", e)
            return False
    # Не дождались Telegram: по ходу задачи журнал догонит на следующем
    # проходе, а итог уйдёт новым сообщением — лишь бы не потерялся.
    return False


DELIVER_TRIES, DELIVER_WAIT = 10, 30     # итог задачи: до ~5 минут ожидания сети


async def _deliver(bot: Bot, chat_id: int, msg_id: int, body: str, markup: InlineKeyboardMarkup) -> None:
    """Итог задачи обязан дойти: правим сообщение, нет его — шлём новое; сеть
    лежит — ждём и пробуем снова. Не вышло — исключение, задача остаётся в
    jobs.json, и resume() после перезапуска бота доставит итог."""
    for attempt in range(1, DELIVER_TRIES + 1):
        try:
            if await _edit(bot, chat_id, msg_id, body, markup):
                return
            await ui.show_new(bot, chat_id, body, markup)
            return
        except TelegramNetworkError as e:
            if attempt == DELIVER_TRIES:
                raise
            log.warning("итог задачи не доставлен (%s), повтор через %s с", e, DELIVER_WAIT)
            await asyncio.sleep(DELIVER_WAIT)


async def _follow(bot: Bot, job_id: str, chat_id: int, msg_id: int, title: str, back_to: str,
                  done: Done | None, started: int | None = None, ok_buttons: list | None = None,
                  bar: str = "") -> None:
    """Слежение за задачей. Любая неожиданная ошибка (сеть, админ заблокировал
    бота…) не должна молча убить задачу в фоне: экран чата снимается с ui.busy,
    а сама задача остаётся в jobs.json — resume() после перезапуска доследит её
    и доставит итог (awg2 хранит задачу три дня, дальше она станет «lost»)."""
    try:
        await _follow_inner(bot, job_id, chat_id, msg_id, title, back_to, done, started, ok_buttons, bar)
    except asyncio.CancelledError:
        raise
    except Exception:                                          # noqa: BLE001
        log.exception("слежение за задачей %s прервано — доследим после перезапуска", job_id)
        ui.busy.discard((chat_id, msg_id))


async def _follow_inner(bot: Bot, job_id: str, chat_id: int, msg_id: int, title: str, back_to: str,
                        done: Done | None, started: int | None, ok_buttons: list | None, bar: str = "") -> None:
    started = started or int(time.time())
    offset, text, shown, last_edit, errors, pct = 0, "", "", 0.0, 0, 0.0
    head = f"<b>{ui.esc(title)}</b>"
    while True:
        await asyncio.sleep(POLL)
        r = await api.job_status(job_id, offset)
        if not r.ok or not isinstance(r.data, dict):
            errors += 1
            if errors < 10:
                continue
            store.job_done(job_id)
            ui.busy.discard((chat_id, msg_id))
            await _edit(bot, chat_id, msg_id, ui.fail(r, title), ui.kb(ui.back(back_to)))
            return
        errors = 0
        st = r.data
        offset = int(st.get("offset") or offset)
        text = (text + (st.get("log") or ""))[-LOG_KEEP:]
        elapsed = ui.fmt_dur(int(time.time()) - started)
        if bar:
            pct = progress.creep(pct, *progress.reached(bar, text))
        if st.get("state") == "running":
            if time.monotonic() - last_edit < EDIT_EVERY:
                continue
            body = (f"⏳ {head} · {elapsed}\n" + (f"<code>{progress.bar(pct)}</code>\n" if bar else "")
                    + (ui.pre(_tail(text), 3500) or "<i>идёт…</i>"))
            if body != shown and await _edit(bot, chat_id, msg_id, body):
                shown, last_edit = body, time.monotonic()
            continue

        ui.busy.discard((chat_id, msg_id))
        if st.get("state") == "lost":
            body = (f"⚠️ {head}\nЗадача прервана: awg2 остановлен или сервер перезагружен.\n"
                    + ui.pre(_tail(text, 15), 2500))
        elif st.get("ok"):
            body = (f"✅ {head} · {elapsed}\n" + (f"<code>{progress.bar(100)}</code>\n" if bar else "")
                    + ui.pre(_tail(text, 20), 3000))
        else:
            body = (f"❌ {head}\n{ui.esc(st.get('error') or 'ошибка')}\n"
                    + (f"<code>{progress.bar(pct)}</code> — остановилось здесь\n" if bar else "")
                    + ui.pre(_tail(text, 20), 3000))
        extra = [tuple(b) for b in ok_buttons or []] if st.get("ok") else []
        markup = ui.kb(extra, ui.back(back_to))
        await _deliver(bot, chat_id, msg_id, body, markup)
        # Задача закрыта только после доставки итога: не дошёл — она остаётся
        # в jobs.json, и resume() после перезапуска доставит его.
        store.job_done(job_id)
        if done and st.get("ok"):
            try:
                await done(bot, chat_id, st)
            except Exception:                                  # noqa: BLE001
                log.exception("действие после задачи %s", job_id)
        return
