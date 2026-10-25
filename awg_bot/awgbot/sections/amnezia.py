"""Перенос из Amnezia (Docker): сервер AWG из контейнера приложения AmneziaVPN
переезжает в awg0 Тулзы с теми же ключами и параметрами — пункт «Сервер →
Перенос из Amnezia» awg2. Конфиги клиентов остаются прежними.

Всё делает awg2 (amnezia scan|migrate|revert|remove), здесь — только экран.
"""

from __future__ import annotations

from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from .. import api, jobs, ui
from ..ui import esc

router = Router()
act = ui.Actions(router, "amz", owner="Перенос из Amnezia делает только владелец")
SHOWN = 25                          # клиентов списком на экране
BLOCK = {"server": "Сервер Тулзы уже создан — перенос только на сервер без своего awg0 (Сервер → ⚠️ Сбросить).",
         "components": "Сначала установи компоненты: Сервер → 📦 Компоненты.",
         "proto": "Модуль ядра не умеет эту версию AWG — обнови его: Сервер → 🧩 Модуль ядра."}


async def found() -> bool:
    """Есть что показать: контейнер Amnezia или сделанный перенос."""
    d = await api.data("amnezia", "status", default={}) or {}
    return bool(d.get("container") or d.get("migrated"))


@act()
async def show(cb: CallbackQuery, state: FSMContext, arg: str = "") -> None:
    await screen(cb)


async def screen(target: ui.Target) -> None:
    await ui.render(target, "⏳ Читаю контейнер Amnezia…")
    r = await api.call("amnezia", "scan", timeout=60)
    if not r.ok or not isinstance(r.data, dict):
        await ui.render(target, ui.fail(r, "Перенос из Amnezia"), ui.kb(ui.back("srv")))
        return
    d = r.data
    head = "<b>🐳 Перенос из Amnezia</b>"
    if d.get("migrated"):
        await ui.render(target, f"{head}\n\n✅ Перенос сделан: сервер работает в Тулзе, контейнер "
                                f"<code>{esc(d.get('container') or '')}</code> остановлен, не удалён.\n\n"
                                "«Вернуть Amnezia» снимает awg0 Тулзы (перед этим — бэкап) и запускает контейнер. "
                                "Когда всё работает — контейнер можно удалить.",
                        ui.kb(("↩️ Вернуть Amnezia", act.data("rev")), ("🗑 Удалить контейнер", act.data("rm")),
                              ui.back("srv")))
        return
    if not d.get("container"):
        await ui.render(target, f"{head}\n\nКонтейнер Amnezia (amnezia-awg2 / amnezia-awg) на сервере не найден.",
                        ui.kb(ui.back("srv")))
        return
    if d.get("error"):
        await ui.render(target, f"{head}\n\n❌ {esc(d['error'])}", ui.kb(ui.back("srv")))
        return
    clients = [c for c in d.get("clients") or [] if isinstance(c, dict)]
    lines = [head, "",
             f"Контейнер <code>{esc(d.get('container', ''))}</code> · {'работает' if d.get('running') else 'остановлен'}",
             f"AWG {esc(str(d.get('proto', '?')))} · порт {d.get('port')}/udp · подсеть <code>{esc(d.get('net', ''))}</code>",
             f"Клиентов: {len(clients)}", ""]
    for c in clients[:SHOWN]:
        orig = c.get("orig") or ""
        lines.append(f"• <code>{esc(c.get('ip', ''))}</code> {esc(c.get('name', ''))}"
                     + (f" ← {esc(orig)}" if orig and orig != c.get("name") else ""))
    if len(clients) > SHOWN:
        lines.append(f"… и ещё {len(clients) - SHOWN}")
    lines += [f"⚠️ {esc(w)}" for w in d.get("warnings") or []]
    lines += [f"❌ {esc(e)}" for e in d.get("errors") or []]
    blockers = [b for b in d.get("blockers") or [] if isinstance(b, str)]
    lines += [f"❌ {esc(BLOCK.get(b, b))}" for b in blockers]
    lines += ["", "Ключи, порт и параметры — те же: клиенты подключаются со своими конфигами, перевыдавать не нужно. "
              "Приватных ключей клиентов на сервере нет — конфиг и QR им Тулза перевыпустит по просьбе.",
              "Приложение AmneziaVPN после переноса этим сервером не управляет (как клиент — работает)."]
    ok = not blockers and not d.get("errors")
    await ui.render(target, "\n".join(lines), ui.kb(
        ("🚚 Перенести", act.data("go")) if ok else None,
        ("📦 Компоненты", "srv:install") if "components" in blockers else None,
        ("🔄 Обновить", act.data()),
        ui.back("srv")))


@act("go")
async def _go(cb: CallbackQuery, state: FSMContext, arg: str) -> None:
    await ui.confirm(cb, "<b>🚚 Перенос из Amnezia</b>\n\nКонтейнер будет остановлен (не удалён), awg0 Тулзы "
                         "поднимется с теми же ключами и портом. Клиенты на пару секунд потеряют связь и "
                         "переподключатся сами. Не поднимется — Amnezia вернётся автоматически.",
                     ("🚚 Перенести", act.data("gook")), "amz")


@act("gook")
async def _go_ok(cb: CallbackQuery, state: FSMContext, arg: str) -> None:
    await jobs.start(cb, "Перенос из Amnezia", "amnezia", "migrate", back_to="amz",
                     ok_buttons=[("👥 Клиенты", "cl")])


@act("rev")
async def _rev(cb: CallbackQuery, state: FSMContext, arg: str) -> None:
    await ui.confirm(cb, "<b>↩️ Вернуть Amnezia</b>\n\nawg0 Тулзы будет снят (перед этим — бэкап), контейнер "
                         "запустится снова. Клиенты, созданные в Тулзе после переноса, в Amnezia не попадут.",
                     ("↩️ Вернуть", act.data("revok")), "amz")


@act("revok")
async def _rev_ok(cb: CallbackQuery, state: FSMContext, arg: str) -> None:
    await jobs.start(cb, "Возврат Amnezia", "amnezia", "revert", back_to="srv")


@act("rm")
async def _rm(cb: CallbackQuery, state: FSMContext, arg: str) -> None:
    await ui.confirm(cb, "<b>🗑 Удалить контейнер Amnezia</b>\n\nКонтейнер удаляется навсегда — вернуть Amnezia "
                         "будет нельзя. Сервер и клиенты в Тулзе остаются.",
                     ("🗑 Удалить", act.data("rmok")), "amz")


@act("rmok")
async def _rm_ok(cb: CallbackQuery, state: FSMContext, arg: str) -> None:
    await ui.result(cb, await api.call("amnezia", "remove", timeout=120), "Удаление контейнера Amnezia", "srv")
