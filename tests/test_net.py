"""
test_net.py — резолвер с запасными адресами Telegram (awgbot/net.py).

Зачем этот тест. Резолвер строится в build_session(), а она вызывается на
импорте bot.py — то есть ДО asyncio.run(). aiohttp.DefaultResolver в
конструкторе берёт текущий цикл событий, поэтому «создать резолвер заранее»
на старте падало с «no running event loop», и запасные адреса молча не
подключались (бот работал, но ровно тем DNS, из-за которого его и чинили).
Ошибка была не видна в тестах, потому что в тестах цикл уже запущен.

Отсюда главная проверка: резолвер должен конструироваться БЕЗ запущенного
цикла, а настоящий DefaultResolver — создаваться лениво, при первом resolve().

Запуск:  python3 tests/test_net.py
Выход:   0 — всё сошлось, 1 — есть провалы.
"""
import asyncio
import os
import socket
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "awg_bot"))

from awgbot import net                                  # noqa: E402

TG = net.TELEGRAM_API_HOST

fail = 0


def chk(name, cond):
    global fail
    if not cond:
        fail += 1
    print(("OK   " if cond else "FAIL ") + name)


def hostrec(ip, port=443):
    return {"hostname": TG, "host": ip, "port": port,
            "family": socket.AF_INET, "proto": 0, "flags": 0}


class LoopBoundResolver:
    """
    Ведёт себя как aiohttp.DefaultResolver: в конструкторе требует
    запущенный цикл. Если настоящий aiohttp установлен — берём его,
    иначе эта заглушка воспроизводит то же условие.
    """

    created = 0
    closed = 0

    def __init__(self):
        asyncio.get_running_loop()      # как DefaultResolver — упадёт вне цикла
        LoopBoundResolver.created += 1

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [hostrec("149.154.167.220", port)]

    async def close(self):
        LoopBoundResolver.closed += 1


class DeadDNS(LoopBoundResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        raise OSError("DNS не отвечает")


def main():
    # --- главная проверка: конструктор вне цикла ---------------------------
    try:
        r = net.TelegramFallbackResolver(LoopBoundResolver)
        chk("конструктор работает без запущенного цикла событий", True)
    except RuntimeError as e:
        chk("конструктор работает без запущенного цикла событий (%s)" % e, False)
        return 1
    chk("базовый резолвер ещё не создан", LoopBoundResolver.created == 0)

    # То же самое с настоящим aiohttp, если он есть: именно его поведение
    # и сломало старт бота.
    try:
        from aiohttp.resolver import DefaultResolver
    except ImportError:
        print("     (aiohttp не установлен — проверка на настоящем DefaultResolver пропущена)")
    else:
        try:
            DefaultResolver()
            print("     (в этой версии aiohttp DefaultResolver вне цикла не падает)")
        except RuntimeError:
            try:
                net.TelegramFallbackResolver(DefaultResolver)
                chk("настоящий DefaultResolver: обёртка строится вне цикла", True)
            except RuntimeError:
                chk("настоящий DefaultResolver: обёртка строится вне цикла", False)

    async def run():
        # --- ленивое создание и подмешивание адресов -----------------------
        got = await r.resolve(TG, 443)
        chk("базовый резолвер создан при первом resolve",
            LoopBoundResolver.created == 1)
        ips = [h["host"] for h in got]
        chk("ответ DNS идёт первым", ips[0] == "149.154.167.220")
        chk("запасные адреса добавлены",
            set(net.TELEGRAM_FALLBACK_IPS).issubset(set(ips)))
        chk("дублей нет", len(ips) == len(set(ips)))
        chk("все записи с обязательными полями aiohttp",
            all({"hostname", "host", "port", "family", "proto", "flags"} <= set(h)
                for h in got))
        chk("порт проброшен во все записи", all(h["port"] == 443 for h in got))

        await r.resolve(TG, 443)
        chk("базовый резолвер создаётся один раз", LoopBoundResolver.created == 1)

        # --- чужие хосты не трогаем ----------------------------------------
        other = await r.resolve("example.org", 443)
        chk("чужой хост отдаётся как есть, без адресов Telegram",
            [h["host"] for h in other] == ["149.154.167.220"])

        # --- DNS не ответил -------------------------------------------------
        dead = net.TelegramFallbackResolver(DeadDNS)
        got = await dead.resolve(TG, 443)
        chk("при мёртвом DNS для Telegram выезжаем на запасных",
            [h["host"] for h in got] == list(net.TELEGRAM_FALLBACK_IPS))
        dead2 = net.TelegramFallbackResolver(DeadDNS)
        try:
            await dead2.resolve("example.org", 443)
            chk("при мёртвом DNS для чужого хоста ошибка поднимается", False)
        except OSError:
            chk("при мёртвом DNS для чужого хоста ошибка поднимается", True)

        # --- close() --------------------------------------------------------
        before = LoopBoundResolver.created
        fresh = net.TelegramFallbackResolver(LoopBoundResolver)
        await fresh.close()
        chk("close() до первого resolve не падает и ничего не создаёт",
            LoopBoundResolver.created == before)
        await r.close()
        chk("close() закрывает базовый резолвер", LoopBoundResolver.closed == 1)
        chk("close() ничего не создал", LoopBoundResolver.created == before)

        # --- без базового резолвера вовсе ------------------------------------
        bare = net.TelegramFallbackResolver()
        got = await bare.resolve(TG, 443)
        chk("без базового резолвера отдаём только запасные адреса",
            [h["host"] for h in got] == list(net.TELEGRAM_FALLBACK_IPS))
        await bare.close()

    asyncio.run(run())

    # --- проверка BOT_PROXY ------------------------------------------------
    chk("пустой прокси — не ошибка", not net.valid_proxy(""))
    chk("socks5:// принимается", net.valid_proxy("socks5://127.0.0.1:1080"))
    chk("http:// принимается", net.valid_proxy("http://1.2.3.4:8080"))
    chk("адрес без схемы отвергается", not net.valid_proxy("127.0.0.1:1080"))
    chk("чужая схема отвергается", not net.valid_proxy("ftp://1.2.3.4:21"))

    # --- сами адреса --------------------------------------------------------
    chk("запасных адресов больше одного", len(net.TELEGRAM_FALLBACK_IPS) > 1)
    chk("все запасные адреса — валидные IPv4",
        all(_is_ipv4(ip) for ip in net.TELEGRAM_FALLBACK_IPS))
    chk("дублей среди запасных адресов нет",
        len(net.TELEGRAM_FALLBACK_IPS) == len(set(net.TELEGRAM_FALLBACK_IPS)))

    print("\nпровалов:", fail)
    return 1 if fail else 0


def _is_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        return False


if __name__ == "__main__":
    sys.exit(main())
