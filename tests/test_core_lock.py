"""
test_core_lock.py — изменения конфига сервера идут строго по одному.

Бот обрабатывает каждое обновление Telegram отдельной задачей и уводит
блокирующие вызовы в asyncio.to_thread, а фоновый мониторинг правит конфиг
сам по себе. Значит, две мутации могут стартовать одновременно из разных
потоков: обе прочитают awg0.conf, обе выберут один и тот же «свободный» IP и
обе перезапишут файл целиком — второй результат затрёт первый.

Тест проверяет и механизм (_serialized действительно не пускает второй поток),
и что им накрыты все функции, которые пишут в конфиг.

Запуск:  python3 tests/test_core_lock.py
Выход:   0 — сошлось, 1 — есть провалы.
"""
import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "awg_bot"))

# core сам по себе ничего не выполняет при импорте, но пути подменяем, чтобы
# случайный вызов не наткнулся на боевой конфиг машины, где гоняют тест.
os.environ.setdefault("AWG_SERVER_CONF", os.path.join(_HERE, "_no_such_awg0.conf"))
os.environ.setdefault("AWG_CLIENT_DIR", _HERE)

from awgbot import core                          # noqa: E402

fail = 0


def chk(name: str, cond: bool, detail: str = "") -> None:
    global fail
    if cond:
        print("  OK   %s" % name)
    else:
        fail += 1
        print("  FAIL %s%s" % (name, (" — " + detail) if detail else ""))


# ── 1. механизм действительно сериализует ──
inside = 0
overlap = False


@core._serialized
def slow(tag: str) -> None:
    global inside, overlap
    inside += 1
    if inside > 1:
        overlap = True
    time.sleep(0.05)
    inside -= 1


threads = [threading.Thread(target=slow, args=("t%d" % i,)) for i in range(6)]
for t in threads:
    t.start()
for t in threads:
    t.join()
chk("два потока не оказались внутри одновременно", not overlap)

# ── 2. вложенный вызов не блокирует сам себя ──
# add_client внутри зовёт apply_syncconf — на обычном Lock это был бы вечный клин.
nested_ok = False


@core._serialized
def outer() -> None:
    global nested_ok
    slow("nested")
    nested_ok = True


t = threading.Thread(target=outer)
t.start()
t.join(timeout=5)
chk("вложенный вызов проходит (RLock, а не Lock)", nested_ok and not t.is_alive())

# ── 3. под замком все мутирующие операции ──
# functools.wraps проставляет __wrapped__ — по нему и видно обёртку.
MUST_BE_LOCKED = [
    "apply_syncconf", "restart_iface", "restore_backup",
    "add_client", "change_client_mimicry", "delete_client", "rename_client",
    "set_expire", "clear_expire", "set_note", "set_monitor",
    "enforce_expirations", "cleanup_legacy_notes",
    "set_dns_upstream", "warp_enable_client", "warp_disable_client",
    "warp_hard_restart",
]
unlocked = [n for n in MUST_BE_LOCKED
            if not hasattr(getattr(core, n, None), "__wrapped__")]
chk("все мутирующие функции под замком", not unlocked, "без замка: %s" % unlocked)

# Чтение конфига замком накрывать не надо: оно и так атомарно на уровне файла,
# а лишний захват заставил бы список клиентов ждать долгую операцию WARP.
READ_ONLY = ["list_peers", "get_peer", "get_server_info", "warp_status", "dns_status"]
locked_reads = [n for n in READ_ONLY
                if hasattr(getattr(core, n, None), "__wrapped__")]
chk("чтение не заперто вместе с записью", not locked_reads, str(locked_reads))

print("\nпровалов:", fail)
sys.exit(1 if fail else 0)
