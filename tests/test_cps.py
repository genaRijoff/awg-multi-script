"""
test_cps.py — структурная проверка CPS-пакетов I1-I5.

Разбирает каждый сгенерированный пакет так, как разбирал бы его получатель:
QUIC Initial расшифровывается ключами из DCID (RFC 9001) и внутри проверяется
ClientHello, DNS/SIP/STUN/DTLS/NTP/RTP/SSDP проверяются по своим форматам.
Смысл теста в том, что мимикрия имеет смысл только пока пакет валиден: битая
длина или отсутствующее обязательное поле выдают подделку вернее, чем её
отсутствие.

Генератор берётся прямо из awg2.sh (блок _CPS_GENERATOR между якорями
CPS_GENERATOR_BEGIN/END v2) — тестируется то, что реально поедет пользователю.

Запуск:  python3 tests/test_cps.py [путь/к/awg2.sh]
Выход:   0 — все пакеты валидны, 1 — есть провалы.
"""
import os, random, re, subprocess, sys, tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
AWG2 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_HERE, "..", "awg2.sh")

_MARKER_RE = re.compile(
    r"# CPS_GENERATOR_BEGIN v2\b.*?^_CPS_GENERATOR='\n(.*?)\n'\n# CPS_GENERATOR_END v2\b",
    re.S | re.M,
)

# Профили и домены, с которыми их прогоняем. Домен один на всю цепочку I1-I5 —
# именно так его передаёт awg2 после выбора в меню.
CASES = [
    ("quic", "ya.ru"),
    ("quic", ""),
    ("curl_quic", "gosuslugi.ru"),
    ("dns", "vk.com"),
    ("dns", ""),
    ("stun", ""),
    ("stun", "ozon.ru"),
    ("webrtc", ""),
    ("sip", "mail.ru"),
    ("ntp", ""),
    ("rtp", ""),
    ("ssdp", ""),
    ("dtls", "avito.ru"),
    ("tls", "dzen.ru"),          # алиас на quic: старые серверы шлют это имя
]

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:                     # без библиотеки проверяем только структуру
    HAVE_CRYPTO = False


def _extract_generator(path):
    src = open(path, encoding="utf-8").read()
    m = _MARKER_RE.search(src)
    if not m:
        sys.exit("не нашёл блок _CPS_GENERATOR (маркеры v2) в %s" % path)
    code = m.group(1)
    compile(code, "<cps>", "exec")          # синтаксис до запуска
    fd, tmp = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)
    return tmp


GEN = _extract_generator(AWG2)


_LETTERS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGITS = b"0123456789"
# Ограничение движка на длину динамического тега (docs.amnezia.org: length <= 1000)
TAG_LEN_MAX = 1000


def parse_line(line):
    """Строка I -> байты пакета, как их соберёт модуль перед отправкой.

    Повторяет модификаторы ядра (junk.c): <b 0x..> — статические байты,
    <r N> — N случайных байт, <rc N> — N букв [A-Za-z], <rd N> — N цифр.
    Каждый вызов даёт НОВЫЙ пакет: jp_spec_applymods пересчитывает эти поля
    перед каждой отправкой, поэтому проверять надо любое их значение.
    """
    tags = re.findall(r"<([^>]*)>", line)
    assert tags, "строка не похожа на CPS-пакет: %r" % line[:40]
    pkt = b""
    for tag in tags:
        if tag.startswith("b 0x"):
            pkt += bytes.fromhex(tag[4:])
            continue
        key, _, val = tag.partition(" ")
        assert key in ("r", "rc", "rd"), "неожиданный тег <%s>" % tag[:10]
        assert val.isdigit(), "длина тега <%s> не число" % tag[:10]
        n = int(val)
        assert 1 <= n <= TAG_LEN_MAX, "<%s %d> вне 1-%d" % (key, n, TAG_LEN_MAX)
        if key == "r":
            pkt += os.urandom(n)
        elif key == "rc":
            pkt += bytes(random.choice(_LETTERS) for _ in range(n))
        else:
            pkt += bytes(random.choice(_DIGITS) for _ in range(n))
    return pkt


def count_tags(line):
    return len(re.findall(r"<(?:r|rc|rd) \d+>", line))


# ── TLS ClientHello: общий разбор для QUIC, DTLS и ECH ──
def parse_client_hello(hs, dtls=False):
    assert hs[0] == 0x01, "не ClientHello"
    hs_len = int.from_bytes(hs[1:4], "big")
    assert hs_len == len(hs) - 4, "длина handshake не совпадает"
    b = hs[4:]
    if dtls:
        assert b[:2] == b"\xfe\xfd", "DTLS: legacy_version не 1.2"
    else:
        assert b[:2] == b"\x03\x03", "legacy_version не 0x0303"
    o = 2 + 32
    sid_len = b[o]; o += 1 + sid_len
    if dtls:
        # у DTLS между session_id и списком шифров стоит cookie (RFC 6347 §4.2.1)
        cookie_len = b[o]; o += 1 + cookie_len
    cs_len = int.from_bytes(b[o:o+2], "big"); o += 2
    assert cs_len % 2 == 0 and cs_len > 0, "битый список шифров"
    o += cs_len
    comp_len = b[o]; o += 1 + comp_len
    assert comp_len == 1 and b[o-1] == 0, "compression должен быть null"
    ext_len = int.from_bytes(b[o:o+2], "big"); o += 2
    assert ext_len == len(b) - o, "длина блока расширений не совпадает"
    exts, end = {}, o + ext_len
    while o < end:
        et = int.from_bytes(b[o:o+2], "big")
        el = int.from_bytes(b[o+2:o+4], "big")
        exts[et] = b[o+4:o+4+el]
        o += 4 + el
    assert o == end, "расширения вышли за границу блока"
    host = ""
    if 0x0000 in exts:
        host = exts[0x0000][5:].decode()
        assert re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", host), "SNI не похож на домен: %r" % host
    return host, exts, cs_len // 2


def read_varint(b, o):
    prefix = b[o] >> 6
    length = 1 << prefix
    value = b[o] & 0x3F
    for i in range(1, length):
        value = (value << 8) | b[o + i]
    return value, o + length


def check_quic(pkt, expect_host=None, expect_ech=False):
    fb = pkt[0]
    assert fb & 0x80 and fb & 0x40, "не long header с установленным fixed bit"
    assert (fb >> 4) & 0x03 == 0, "long header, но не Initial"
    assert pkt[1:5] == b"\x00\x00\x00\x01", "версия не QUIC v1"
    o = 5
    dl = pkt[o]; o += 1 + dl
    sl = pkt[o]; o += 1 + sl
    assert 0 < dl <= 20 and sl <= 20, "странные длины CID"
    token_len, o = read_varint(pkt, o)
    assert token_len == 0, "у клиентского Initial должен быть пустой token"
    length_off = o
    plen, o = read_varint(pkt, length_off)
    assert o + plen == len(pkt), "поле length не сходится с датаграммой"
    assert len(pkt) >= 1200, "RFC 9000 §14.1: клиентский Initial < 1200 байт"
    if not HAVE_CRYPTO:
        return "QUIC Initial ok: %d байт (без расшифровки)" % len(pkt)

    # снимаем header protection и расшифровываем — ключи выводятся из DCID
    import hmac, hashlib
    dcid = pkt[6:6+dl]
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    def expand(secret, label, length):
        lb = b"tls13 " + label
        info = length.to_bytes(2, "big") + bytes([len(lb)]) + lb + b"\x00"
        out, block, counter = b"", b"", 1
        while len(out) < length:
            block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
            out += block; counter += 1
        return out[:length]
    initial = hmac.new(salt, dcid, hashlib.sha256).digest()
    client = expand(initial, b"client in", 32)
    key, iv, hp = (expand(client, b"quic key", 16), expand(client, b"quic iv", 12),
                   expand(client, b"quic hp", 16))
    pn_off = o
    sample = pkt[pn_off+4:pn_off+4+16]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn = bytes(pkt[pn_off+i] ^ mask[1+i] for i in range(pn_len))
    header = bytes([first]) + pkt[1:pn_off] + pn
    nonce = bytearray(iv)
    for i, byte in enumerate(pn):
        nonce[len(nonce)-len(pn)+i] ^= byte
    plain = AESGCM(key).decrypt(bytes(nonce), pkt[pn_off+pn_len:], header)
    assert plain[0] == 0x06, "первый фрейм не CRYPTO"
    frame_off, p = read_varint(plain, 1)
    frame_len, p = read_varint(plain, p)
    assert frame_off == 0, "CRYPTO-фрейм с ненулевым offset"
    host, exts, ciphers = parse_client_hello(plain[p:p+frame_len])
    assert set(plain[p+frame_len:]) <= {0}, "хвост датаграммы не PADDING"
    assert 0x0039 in exts, "нет quic_transport_parameters"
    assert 0x0010 in exts and b"h3" in exts[0x0010], "нет ALPN h3"
    if expect_ech:
        assert 0xFE0D in exts, "профиль curl_quic без расширения ECH"
    if expect_host and not expect_ech:
        assert host == expect_host, "SNI %r вместо %r" % (host, expect_host)
    return "QUIC Initial ok: %d Б, SNI=%s, шифров=%d%s" % (
        len(pkt), host or "-", ciphers, ", ECH" if 0xFE0D in exts else "")


def check_dns(pkt, expect_host=None):
    assert pkt[2:4] == b"\x01\x00", "флаги не standard query+RD"
    qd, an, ns, ar = (int.from_bytes(pkt[i:i+2], "big") for i in (4, 6, 8, 10))
    assert (qd, an, ns, ar) == (1, 0, 0, 1), "counts не 1/0/0/1: %s" % ((qd, an, ns, ar),)
    o, labels = 12, []
    while pkt[o]:
        ln = pkt[o]
        assert ln <= 63, "label > 63"
        labels.append(pkt[o+1:o+1+ln].decode()); o += 1 + ln
    o += 1
    qt, qc = int.from_bytes(pkt[o:o+2], "big"), int.from_bytes(pkt[o+2:o+4], "big")
    assert qt in (1, 28, 65), "qtype %d не A/AAAA/HTTPS" % qt
    assert qc == 1, "qclass не IN"
    o += 4
    assert pkt[o] == 0 and int.from_bytes(pkt[o+1:o+3], "big") == 41, "нет OPT RR (EDNS0)"
    assert o + 11 == len(pkt), "хвост после OPT RR"
    host = ".".join(labels)
    if expect_host:
        assert host == expect_host, "QNAME %r вместо %r" % (host, expect_host)
    return "DNS query ok: %s, qtype=%d, EDNS0" % (host, qt)


def check_sip(pkt, expect_host=None):
    txt = pkt.decode()
    assert "\r\n\r\n" in txt, "нет пустой строки между заголовками и телом"
    head, _, body = txt.partition("\r\n\r\n")
    lines = head.split("\r\n")
    m = re.fullmatch(r"(REGISTER|OPTIONS|INVITE) sip:[a-zA-Z0-9.@\-]+ SIP/2\.0", lines[0]) or \
        re.fullmatch(r"SIP/2\.0 100 CONNECTING", lines[0])
    assert m, "битая первая строка: %r" % lines[0]
    method = lines[0].split(" ")[0]
    hdr = {k.lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:])}
    for need in ("via", "from", "to", "call-id", "cseq", "content-length"):
        assert need in hdr, "нет обязательного заголовка %s" % need
    assert hdr["via"].startswith("SIP/2.0/"), "битый Via"
    assert "branch=z9hG4bK" in hdr["via"], "branch не по RFC 3261 (magic cookie)"
    assert ";tag=" in hdr["from"], "нет tag в From"
    assert hdr["content-length"].isdigit(), "Content-Length не число"
    assert int(hdr["content-length"]) == len(body.encode()), (
        "Content-Length %s не совпадает с телом (%d байт)"
        % (hdr["content-length"], len(body.encode())))
    if expect_host:
        assert expect_host in hdr["call-id"], "домен %r не попал в Call-ID" % expect_host
    return "SIP %s ok: заголовков=%d" % (method, len(hdr))


def check_stun(pkt, expect_host=None, offset=0, allow_tail=False):
    mt = int.from_bytes(pkt[offset:offset+2], "big")
    assert mt in (0x0001, 0x000A), "тип сообщения %#06x не Binding и не Allocate" % mt
    mlen = int.from_bytes(pkt[offset+2:offset+4], "big")
    assert pkt[offset+4:offset+8] == b"\x21\x12\xa4\x42", "нет magic cookie"
    end = offset + 20 + mlen
    if not allow_tail:
        assert end == len(pkt), "длина STUN не сходится (%d vs %d)" % (end, len(pkt))
    o, attrs = offset + 20, {}
    while o + 4 <= end:
        at = int.from_bytes(pkt[o:o+2], "big")
        al = int.from_bytes(pkt[o+2:o+4], "big")
        attrs[at] = pkt[o+4:o+4+al]
        o += 4 + al + ((4 - (al % 4)) % 4)
    assert o == end, "атрибуты вышли за границу сообщения"
    assert 0x0006 in attrs, "нет USERNAME"
    assert 0x8028 in attrs, "нет FINGERPRINT"
    # SOFTWARE в STUN необязателен (RFC 5389 §15.10). Он есть, когда пакет
    # изображает клиента известного провайдера, и его НЕ должно быть, когда
    # хост подменён своим доменом: вендорское имя рядом с чужим хостом — та
    # самая несостыковка, ради устранения которой атрибут и убирается.
    if expect_host:
        assert 0x8022 not in attrs, (
            "при своём домене остался вендорский SOFTWARE: %r" % attrs[0x8022])
        assert attrs.get(0x0014, expect_host.encode()) == expect_host.encode(), (
            "REALM %r не совпал со своим доменом" % attrs.get(0x0014))
    else:
        assert 0x8022 in attrs, "нет SOFTWARE"
    import zlib
    crc = (zlib.crc32(pkt[offset:end-8]) ^ 0x5354554E) & 0xFFFFFFFF
    assert int.from_bytes(attrs[0x8028], "big") == crc, "FINGERPRINT не сходится с CRC32"
    if mt == 0x000A:
        assert 0x0019 in attrs, "Allocate без REQUESTED-TRANSPORT"
        assert 0x000D in attrs, "Allocate без LIFETIME"
    if expect_host:
        assert expect_host.encode() in attrs[0x0006], "домен не попал в USERNAME"
    return "STUN %s ok: атрибутов=%d, FINGERPRINT сходится" % (
        "Allocate" if mt == 0x000A else "Binding", len(attrs)), end


def check_dtls(pkt, expect_host=None, offset=0):
    assert pkt[offset] == 0x16, "не DTLS handshake record"
    assert pkt[offset+1:offset+3] == b"\xfe\xfd", "версия записи не DTLS 1.2"
    rec_len = int.from_bytes(pkt[offset+11:offset+13], "big")
    end = offset + 13 + rec_len
    hs = pkt[offset+13:end]
    assert hs[0] == 0x01, "не ClientHello"
    body_len = int.from_bytes(hs[1:4], "big")
    frag_len = int.from_bytes(hs[9:12], "big")
    assert body_len == frag_len, "фрагмент DTLS не равен длине сообщения"
    host, exts, ciphers = parse_client_hello(hs[:4] + hs[12:], dtls=True)
    assert 0x000E in exts, "нет use_srtp — для DTLS-SRTP это обязательный признак"
    if expect_host:
        assert host == expect_host, "SNI %r вместо %r" % (host, expect_host)
    return "DTLS ClientHello ok: SNI=%s, шифров=%d" % (host or "-", ciphers), end


def check_ntp(pkt):
    assert len(pkt) == 48, "NTP-пакет должен быть 48 байт, а он %d" % len(pkt)
    li_vn_mode = pkt[0]
    assert (li_vn_mode >> 3) & 0x07 == 4, "версия NTP не 4"
    assert li_vn_mode & 0x07 == 3, "режим не client (3)"
    assert pkt[12:16] == b"INIT", "нет reference id INIT"
    return "NTP client ok: 48 Б, v4 mode 3"


def check_rtp(pkt):
    assert (pkt[0] >> 6) == 2, "версия RTP не 2"
    assert pkt[0] & 0x0F == 0, "CSRC count должен быть 0"
    pt = pkt[1] & 0x7F
    assert pt in (0, 8, 96), "payload type %d не из профиля" % pt
    assert len(pkt) > 12, "RTP без полезной нагрузки"
    return "RTP ok: pt=%d, %d Б payload" % (pt, len(pkt) - 12)


def check_ssdp(pkt):
    txt = pkt.decode()
    assert txt.startswith("M-SEARCH * HTTP/1.1\r\n"), "не M-SEARCH"
    assert txt.endswith("\r\n\r\n"), "нет завершающей пустой строки"
    hdr = {}
    for line in txt.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdr[k.lower()] = v.strip()
    for need in ("host", "man", "st", "mx"):
        assert need in hdr, "нет обязательного заголовка %s" % need
    assert hdr["host"] == "239.255.255.250:1900", "HOST не мультикастовый адрес SSDP"
    assert hdr["man"] == '"ssdp:discover"', "MAN не ssdp:discover"
    assert hdr["mx"].isdigit() and 1 <= int(hdr["mx"]) <= 5, "MX вне 1-5"
    return "SSDP M-SEARCH ok: ST=%s" % hdr["st"]


def stun_attrs(pkt, offset=0):
    """Атрибуты STUN-сообщения — для проверок, общих на всю цепочку I1-I5."""
    end = offset + 20 + int.from_bytes(pkt[offset+2:offset+4], "big")
    o, attrs = offset + 20, {}
    while o + 4 <= end:
        at = int.from_bytes(pkt[o:o+2], "big")
        al = int.from_bytes(pkt[o+2:o+4], "big")
        attrs[at] = pkt[o+4:o+4+al]
        o += 4 + al + ((4 - (al % 4)) % 4)
    return attrs


def dns_query_type(pkt):
    """QTYPE вопроса: он стоит перед QCLASS, а дальше только запись OPT (11 байт)."""
    return int.from_bytes(pkt[-15:-13], "big")


def check_webrtc(pkt):
    # STUN Binding + DTLS ClientHello + RTP + RTCP одним пакетом
    msg, end = check_stun(pkt, offset=0, allow_tail=True)
    dtls_msg, end = check_dtls(pkt, offset=end)
    rtp_off = end
    assert (pkt[rtp_off] >> 6) == 2, "после DTLS нет RTP"
    assert pkt[-1:] != b"", "пустой хвост"
    return "WebRTC ok: %s + %s + RTP/RTCP, %d Б" % (msg, dtls_msg, len(pkt))


def check_packet(profile, pkt, domain):
    if profile in ("quic", "tls"):
        return check_quic(pkt, expect_host=domain or None)
    if profile == "curl_quic":
        return check_quic(pkt, expect_host=domain or None, expect_ech=True)
    if profile == "dns":
        return check_dns(pkt, expect_host=domain or None)
    if profile == "sip":
        return check_sip(pkt, expect_host=domain or None)
    if profile == "stun":
        return check_stun(pkt, expect_host=domain or None)[0]
    if profile == "webrtc":
        return check_webrtc(pkt)
    if profile == "dtls":
        return check_dtls(pkt, expect_host=domain or None)[0]
    if profile == "ntp":
        return check_ntp(pkt)
    if profile == "rtp":
        return check_rtp(pkt)
    return check_ssdp(pkt)


# Профили, у которых пакет ОБЯЗАН содержать динамические поля: без них строка I
# уходит байт в байт одинаковой при каждом рукопожатии (раз в ~120 с), а это
# ровно тот повторяющийся паттерн, ради устранения которого делалась 3.1.
DYNAMIC_PROFILES = {"dns", "sip", "ntp", "rtp", "dtls", "webrtc"}
# Профили, где динамическое поле сломало бы пакет: STUN накрыт FINGERPRINT
# (CRC32 по всему сообщению), QUIC Initial — AEAD с ключами из DCID, SSDP в
# жизни и так повторяется дословно.
STATIC_PROFILES = {"quic", "curl_quic", "tls", "stun", "ssdp"}

fail = 0
for profile, domain in CASES:
    args = ["python3", GEN, profile] + ([domain] if domain else [])
    proc = subprocess.run(args, capture_output=True, text=True)
    out = [l for l in proc.stdout.splitlines() if l.strip()]
    label = "%s/%s" % (profile, domain or "auto")
    if len(out) != 5:
        fail += 1
        print("  FAIL %-22s ожидали 5 пакетов, получили %d (%s)"
              % (label, len(out), proc.stderr.strip()[:60]))
        continue
    for i, line in enumerate(out, 1):
        try:
            pkt = parse_line(line)
            msg = check_packet(profile, pkt, domain)
            tags = count_tags(line)
            if tags:
                # Второе разворачивание тегов — другой набор случайных полей.
                # Пакет обязан остаться валидным при ЛЮБОМ их значении, иначе
                # мимикрия ломается на второй же отправке.
                other = parse_line(line)
                check_packet(profile, other, domain)
                assert other != pkt, "теги есть, а пакет не изменился"
                msg += "; динамических полей %d" % tags
            if profile in DYNAMIC_PROFILES:
                assert tags, "профиль без динамических полей: строка замрёт навсегда"
            if profile in STATIC_PROFILES:
                assert not tags, "у этого профиля тег ломает контрольную сумму/AEAD"
            print("  OK  %-22s I%d %5dB  %s" % (label, i, len(pkt), msg))
        except Exception as e:
            fail += 1
            print("  FAIL %-21s I%d %5dB  %s: %s"
                  % (label, i, len(line) // 2, type(e).__name__, e))

    # ── связность ЦЕПОЧКИ, а не отдельного пакета ──
    # Пакеты I1-I5 уходят подряд от одного клиента, поэтому смотреть их надо
    # вместе: по отдельности каждый может быть безупречен, а вместе они выдают
    # то, чего в жизни не бывает.
    try:
        packets = [parse_line(line) for line in out]
        if profile in ("stun", "webrtc"):
            softwares = {bytes(stun_attrs(p).get(0x8022, b"")) for p in packets}
            assert len(softwares) == 1, (
                "клиент представился по-разному в одной цепочке: %s"
                % sorted(x.decode(errors="replace") for x in softwares))
            # Строки-заглушки в креденшелах — прямая сигнатура: их можно искать
            # байтовым сравнением, без всякой статистики.
            usernames = b" ".join(stun_attrs(p).get(0x0006, b"") for p in packets)
            for literal in (b"a1b2c3d4e5f6g7h8i9j0", b"abcdef1234567890abcd",
                            b"1a2b3c4d5e6f7g8h9i0j", b"1234567890abcdef1234"):
                assert literal not in usernames, (
                    "в USERNAME литеральная заглушка %r" % literal)
            who = list(softwares)[0].decode(errors="replace") or "без SOFTWARE"
            print("  OK  %-22s цепочка: один клиент (%s), креденшелы случайны"
                  % (label, who))
        if profile == "dns":
            qtypes = [dns_query_type(p) for p in packets]
            assert len(set(qtypes)) > 1, (
                "вся цепочка спрашивает один тип записи: %s" % qtypes)
            adjacent = [a for a, b in zip(qtypes, qtypes[1:]) if a == b]
            assert not adjacent, "два одинаковых запроса подряд: %s" % qtypes
            print("  OK  %-22s цепочка: типы запросов %s" % (label, qtypes))
    except Exception as e:
        fail += 1
        print("  FAIL %-21s цепочка  %s: %s" % (label, type(e).__name__, e))

os.unlink(GEN)
print("\nпровалов:", fail)
sys.exit(1 if fail else 0)
