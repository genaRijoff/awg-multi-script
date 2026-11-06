"""Точки входа (каскад): клиент подключается не к серверу напрямую, а через
сервер-вход — любой сервер, где UDP-порт проброшен на этот (каскад Тулзы,
iptables, nginx stream). В конфиге такого клиента Endpoint — адрес входа.
Пункт «Сервер → Endpoint → Точки входа» awg2.

Здесь — список, добавление, адрес, проверка, вход для новых клиентов,
перевод всех клиентов и удаление. Вход одного клиента — кнопкой «📍 Вход» в
его карточке (clients.py).
"""

from __future__ import annotations

from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from .. import api, ask, ui
from ..ui import esc

router = Router()
act = ui.Actions(router, "ent")
TITLE = "Точки входа"
NAME_MAX = 24


async def entries() -> list[dict] | None:
    """Строки awg2 api entry list; первая — «напрямую» (name пустое)."""
    r = await api.call("entry", "list")
    return r.data if r.ok and isinstance(r.data, list) else None


def label(e: dict) -> str:
    return e.get("name") or "Напрямую"


def arg(name: str) -> str:
    """Имя для awg2: «напрямую» — direct."""
    return name or "direct"


@act()
async def show(cb: CallbackQuery, state: FSMContext, arg_: str = "") -> None:
    await screen(cb, state)


async def screen(target: ui.Target, state: FSMContext) -> None:
    rows = await entries()
    if rows is None:
        r = await api.call("entry", "list")
        await ui.render(target, ui.fail(r, TITLE), ui.kb(ui.back("srv")))
        return
    # Имена — в FSM: в callback_data (64 байта) кириллица длиной 24 не влезет
    await ui.remember(state, "entry", [e["name"] for e in rows])
    lines = [f"<b>📍 {TITLE}</b>", "",
             "Клиент подключается через сервер-вход — любой сервер, где UDP-порт проброшен на этот "
             "(каскад). В конфиге и QR такого клиента Endpoint — адрес входа, остальное как у всех.", ""]
    for e in rows:
        lines.append(f"{'⭐' if e.get('default') else '•'} <b>{esc(label(e))}</b> — "
                     f"<code>{esc(e.get('addr', ''))}</code>, клиентов {e.get('clients', 0)}")
    lines += ["", "⭐ — вход для новых клиентов. Вход клиента — «📍 Вход» в его карточке."]
    await ui.render(target, "\n".join(lines), ui.kb(
        [(("⭐ " if e.get("default") else "") + label(e), act.data("e", str(i))) for i, e in enumerate(rows)],
        ("➕ Добавить", act.data("add")) if len(rows) <= 20 else None,
        ui.back("srv")))


async def _entry(state: FSMContext, idx: str) -> tuple[str, dict] | None:
    name = await ui.recall(state, "entry", idx)
    if name is None:
        return None
    rows = await entries() or []
    e = next((r for r in rows if r.get("name") == name), None)
    return (name, e) if e else None


async def _gone(cb: CallbackQuery, state: FSMContext) -> None:
    await cb.answer("Точки входа уже нет — список обновлён")
    await screen(cb, state)


@act("e")
async def _card(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    await card(cb, state, idx)


async def card(target: ui.Target, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None:
        await ui.render(target, "Точки входа уже нет.", ui.kb(ui.back(act.data())))
        return
    name, e = got
    lines = [f"<b>📍 {esc(label(e))}</b>", "",
             f"Адрес: <code>{esc(e.get('addr', ''))}</code>",
             f"Клиентов: {e.get('clients', 0)}",
             "Для новых клиентов: " + ("⭐ да" if e.get("default") else "нет")]
    if not name:
        lines += ["", "<i>Напрямую — этот сервер: IP или домен из «🌍 Endpoint».</i>"]
    await ui.render(target, "\n".join(lines), ui.kb(
        ("🩺 Проверить", act.data("chk", idx)) if name else None,
        ("✏️ Адрес", act.data("addr", idx)) if name else None,
        ("⭐ Для новых", act.data("def", idx)) if not e.get("default") else None,
        ("👥 Всех сюда", act.data("all", idx)),
        ("🗑 Удалить", act.data("del", idx)) if name else None,
        ui.back(act.data())))


@act("chk")
async def _check(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None:
        await _gone(cb, state)
        return
    await ui.render(cb, f"⏳ Проверяю вход «{esc(got[0])}»…")
    await ui.result(cb, await api.call("entry", "check", got[0]), f"Проверка «{got[0]}»", act.data("e", idx))


@act("def")
async def _default(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None:
        await _gone(cb, state)
        return
    r = await api.call("entry", "default", arg(got[0]))
    if not r.ok:
        await ui.render(cb, ui.fail(r, TITLE), ui.kb(ui.back(act.data("e", idx))))
        return
    await cb.answer(f"Новые клиенты — {'напрямую' if not got[0] else 'через «' + got[0] + '»'}")
    await card(cb, state, idx)


@act("all")
async def _all(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None:
        await _gone(cb, state)
        return
    await ui.confirm(cb, f"<b>👥 Все клиенты → {esc(label(got[1]))}</b>\n\nEndpoint перепишется во всех "
                         f"конфигах на <code>{esc(got[1].get('addr', ''))}</code>. Каждому клиенту нужен новый "
                         "конфиг или QR — в старом прежний адрес.",
                     ("✅ Перевести", act.data("allok", idx)), act.data("e", idx))


@act("allok")
async def _all_ok(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None:
        await _gone(cb, state)
        return
    await ui.result(cb, await api.call("entry", "all", arg(got[0]), timeout=300), TITLE, act.data())


@act("del")
async def _del(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None or not got[0]:
        await _gone(cb, state)
        return
    n = got[1].get("clients", 0)
    await ui.confirm(cb, f"Удалить точку входа <b>{esc(got[0])}</b>?"
                         + (f"\n\nЕё клиенты ({n}) перейдут на «напрямую» — им нужен новый конфиг." if n else ""),
                     ("🗑 Удалить", act.data("delok", idx)), act.data("e", idx))


@act("delok")
async def _del_ok(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None or not got[0]:
        await _gone(cb, state)
        return
    await ui.result(cb, await api.call("entry", "del", got[0], timeout=300), TITLE, act.data())


ADDR_HINT = ("Адрес сервера-входа и порт, который проброшен на этот сервер: "
             "<code>203.0.113.5:443</code> или <code>vpn.example.com:443</code>")


@act("addr")
async def _addr(cb: CallbackQuery, state: FSMContext, idx: str) -> None:
    got = await _entry(state, idx)
    if got is None or not got[0]:
        await _gone(cb, state)
        return
    await ask.ask(cb, state, "ent_set", f"Новый адрес «{esc(got[0])}».\n{ADDR_HINT}", act.data("e", idx),
                  name=got[0], idx=idx)


@ask.on("ent_set")
async def _addr_answer(msg: Message, state: FSMContext, ctx: ask.Ctx) -> None:
    v = ask.text_of(msg).replace(" ", "")
    if ":" not in v:
        await ask.retry(msg, state, ctx, "Нужен хост:порт")
        return
    await ui.render(msg, "⏳ Меняю адрес и проверяю вход…")
    await ui.result(msg, await api.call("entry", "set", ctx["name"], v, timeout=300), TITLE, act.data("e", ctx["idx"]))


@act("add")
async def _add(cb: CallbackQuery, state: FSMContext, arg_: str) -> None:
    await ask.ask(cb, state, "ent_name", "Название точки входа, например <code>Каскад NL</code> — "
                                         f"буквы, цифры, пробел, точка, _ и -, до {NAME_MAX} символов.",
                  act.data())


@ask.on("ent_name")
async def _add_name(msg: Message, state: FSMContext, ctx: ask.Ctx) -> None:
    name = " ".join(ask.text_of(msg).split())
    if not name or len(name) > NAME_MAX or any(ch in name for ch in "|,=#"):
        await ask.retry(msg, state, ctx, f"Название — до {NAME_MAX} символов: буквы, цифры, пробел, точка, _ и -")
        return
    await ask.ask(msg, state, "ent_add", f"Вход «{esc(name)}».\n{ADDR_HINT}", act.data(), name=name)


@ask.on("ent_add")
async def _add_addr(msg: Message, state: FSMContext, ctx: ask.Ctx) -> None:
    v = ask.text_of(msg).replace(" ", "")
    if ":" not in v:
        await ask.retry(msg, state, ctx, "Нужен хост:порт")
        return
    await ui.render(msg, "⏳ Добавляю и проверяю вход…")
    await ui.result(msg, await api.call("entry", "add", ctx["name"], v), TITLE, act.data())
