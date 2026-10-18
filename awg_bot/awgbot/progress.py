"""progress.py — шкала долгих задач обновления (бот и панель — одни этапы).

Этапы — строки, которые пишут awg2 и установщик бота по ходу дела; доля —
сколько от всей задачи обычно пройдено к этому месту. Между этапами шкала
не стоит: подтягивается к следующему, но не дальше него. Тот же список — в
webapp/app.js (JOB_STAGES): правишь здесь — правь и там.
"""

from __future__ import annotations

import re

STAGES: dict[str, list[tuple[str, int]]] = {
    # awg2 update install [force]
    "update": [(r"Канал:", 10), (r"Через зеркало", 20), (r"Прежняя версия|Уже последняя", 75),
               (r"Установлено:", 92)],
    # awg2 bot update: установщик бота
    "bot": [(r"Установщик бота|Найден локальный код", 5), (r"Скачиваю код бота|Код бота:", 15),
            (r"Зависимости Python", 30), (r"Код и зависимости:", 75), (r"Веб-панель перезапущена", 85),
            (r"Бот перезапущен", 92)],
}


def kind(args: tuple) -> str:
    """Какая шкала у задачи: "" — без шкалы."""
    a = [str(x) for x in args[:2]]
    if a == ["update", "install"]:
        return "update"
    if a == ["bot", "update"]:
        return "bot"
    return ""


def reached(k: str, text: str) -> tuple[int, int]:
    """(доля пройденного этапа, доля следующего) по журналу задачи."""
    stages = STAGES.get(k, [])
    got, nxt = 0, (stages[0][1] if stages else 100)
    for i, (pat, pct) in enumerate(stages):
        if re.search(pat, text):
            got = max(got, pct)
            later = [p for _, p in stages[i + 1:]]
            nxt = later[0] if later else 100
    return got, nxt


def creep(pct: float, got: int, nxt: int) -> float:
    """Следующее значение шкалы: не меньше пройденного, к следующему этапу —
    понемногу, но не дальше него."""
    pct = max(pct, float(got))
    return min(pct + (nxt - pct) * 0.08, nxt - 1.0) if pct < nxt - 1 else pct


def bar(pct: float, width: int = 12) -> str:
    """«▓▓▓▓░░░░░░░░ 33%» — для сообщения в Telegram."""
    n = max(0, min(width, round(pct * width / 100)))
    return "▓" * n + "░" * (width - n) + f" {int(pct)}%"
