"""
test_cps.py — структурная проверка CPS-пакетов I1-I5.

Разбирает каждый сгенерированный пакет так, как разбирал бы его DPI: TLS
ClientHello, DNS query, SIP REGISTER и QUIC Initial/1-RTT. Смысл теста в том,
что пакеты урезаны ради экономии трафика, и «короче» не должно означать
«невалидно»: сломанная длина или отсутствующий обязательный заголовок делают
мимикрию хуже, чем её отсутствие.

Генератор берётся прямо из awg2.sh (блок _CPS_GENERATOR между якорями
CPS_GENERATOR_BEGIN/END) — тестируется то, что реально поедет пользователю.

Запуск:  python3 tests/test_cps.py [путь/к/awg2.sh]
Выход:   0 — все пакеты валидны, 1 — есть провалы.
"""
import os, re, subprocess, sys, tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
AWG2 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_HERE, "..", "awg2.sh")

_MARKER_RE = re.compile(
    r"# CPS_GENERATOR_BEGIN v1\b.*?^_CPS_GENERATOR='\n(.*?)\n'\n# CPS_GENERATOR_END v1\b",
    re.S | re.M,
)


def _extract_generator(path):
    src = open(path, encoding="utf-8").read()
    m = _MARKER_RE.search(src)
    if not m:
        sys.exit("не нашёл блок _CPS_GENERATOR в %s" % path)
    code = m.group(1)
    compile(code, "<cps>", "exec")          # синтаксис до запуска
    fd, tmp = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)
    return tmp


GEN = _extract_generator(AWG2)

def parse_line(line):
    """<r N><b 0x..> -> (префикс случайных байт, пакет)"""
    rnd, pkt = 0, b""
    for tag in re.findall(r"<([^>]*)>", line):
        if tag.startswith("b 0x"):
            pkt += bytes.fromhex(tag[4:])
        elif tag.startswith("r "):
            rnd += int(tag[2:])
        else:
            raise AssertionError("неизвестный тег <%s>" % tag)
    return rnd, pkt

def check_tls(pkt):
    assert pkt[0] == 0x16, "не TLS handshake record"
    assert pkt[1:3] == b"\x03\x01", "legacy record version не 0x0301"
    rec_len = int.from_bytes(pkt[3:5], "big")
    assert rec_len == len(pkt) - 5, "длина record не совпадает (%d vs %d)" % (rec_len, len(pkt) - 5)
    hs = pkt[5:]
    assert hs[0] == 0x01, "не ClientHello"
    hs_len = int.from_bytes(hs[1:4], "big")
    assert hs_len == len(hs) - 4, "длина handshake не совпадает"
    b = hs[4:]
    assert b[:2] == b"\x03\x03", "legacy_version не 0x0303"
    o = 2 + 32
    sid_len = b[o]; o += 1 + sid_len
    assert sid_len in (0, 32), "странная длина session_id"
    cs_len = int.from_bytes(b[o:o+2], "big"); o += 2
    assert cs_len % 2 == 0 and cs_len > 0, "битый список шифров"
    o += cs_len
    comp_len = b[o]; o += 1 + comp_len
    assert comp_len == 1 and b[o-1] == 0, "compression должен быть null"
    ext_len = int.from_bytes(b[o:o+2], "big"); o += 2
    assert ext_len == len(b) - o, "длина блока расширений не совпадает"
    exts, end = {}, o + ext_len
    while o < end:
        et = int.from_bytes(b[o:o+2], "big"); el = int.from_bytes(b[o+2:o+4], "big")
        exts[et] = b[o+4:o+4+el]; o += 4 + el
    assert o == end, "расширения вышли за границу блока"
    assert 0x0000 in exts, "нет SNI"
    host = exts[0x0000][5:].decode()
    assert re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", host), "SNI не похож на домен: %r" % host
    assert 0x002b in exts and b"\x03\x04" in exts[0x002b], "нет supported_versions с TLS 1.3"
    ks = exts.get(0x0033); assert ks, "нет key_share"
    assert b"\x00\x1d\x00\x20" in ks, "нет x25519-ключа длиной 32"
    assert 0x000d in exts and len(exts[0x000d]) >= 4, "нет signature_algorithms"
    assert 0x0010 in exts and b"h2" in exts[0x0010], "нет ALPN h2"
    assert 0x000a in exts, "нет supported_groups"
    return "TLS ClientHello ok: SNI=%s, ext=%d, шифров=%d" % (host, len(exts), cs_len // 2)

def check_dns(rnd, pkt):
    assert rnd == 2, "нет случайного transaction ID (<r 2>)"
    assert pkt[0:2] == b"\x01\x00", "флаги не standard query+RD"
    qd, an, ns, ar = (int.from_bytes(pkt[i:i+2], "big") for i in (2, 4, 6, 8))
    assert (qd, an, ns, ar) == (1, 0, 0, 1), "counts не 1/0/0/1: %s" % ((qd, an, ns, ar),)
    o, labels = 10, []
    while pkt[o]:
        ln = pkt[o]; assert ln <= 63, "label > 63"
        labels.append(pkt[o+1:o+1+ln].decode()); o += 1 + ln
    o += 1
    qt, qc = int.from_bytes(pkt[o:o+2], "big"), int.from_bytes(pkt[o+2:o+4], "big")
    assert qt in (1, 28, 16, 65), "qtype %d не A/AAAA/TXT/HTTPS" % qt
    assert qc == 1, "qclass не IN"
    o += 4
    assert pkt[o] == 0 and int.from_bytes(pkt[o+1:o+3], "big") == 41, "нет OPT RR (EDNS0)"
    assert o + 11 == len(pkt), "хвост после OPT RR"
    return "DNS query ok: %s, qtype=%d, EDNS0" % (".".join(labels), qt)

def check_sip(pkt):
    txt = pkt.decode()
    assert txt.endswith("\r\n\r\n"), "нет пустой строки в конце"
    head, _, body = txt.partition("\r\n\r\n")
    lines = head.split("\r\n")
    m = re.fullmatch(r"(REGISTER|OPTIONS) sip:[a-z0-9.\-]+ SIP/2\.0", lines[0])
    assert m, "битая request-line: %r" % lines[0]
    method = m.group(1)
    hdr = {k.lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:])}
    for need in ("via", "from", "to", "call-id", "cseq", "max-forwards", "content-length"):
        assert need in hdr, "нет обязательного заголовка %s" % need
    assert hdr["via"].startswith("SIP/2.0/"), "битый Via"
    assert "branch=z9hG4bK" in hdr["via"], "branch не по RFC 3261 (magic cookie)"
    assert ";tag=" in hdr["from"], "нет tag в From"
    assert re.fullmatch(r"\d+ " + method, hdr["cseq"]), "CSeq не совпадает с методом"
    assert hdr["content-length"] == "0" and body == "", "Content-Length не соответствует телу"
    if method == "REGISTER":
        assert "contact" in hdr, "REGISTER без Contact"
    return "SIP %s ok: заголовков=%d" % (method, len(hdr))

def check_quic(pkt, first=False):
    fb = pkt[0]
    if fb & 0x80:
        assert fb & 0x40, "fixed bit не установлен"
        ptype = (fb >> 4) & 0x03
        assert ptype == 0, "long header, но не Initial"
        assert pkt[1:5] == b"\x00\x00\x00\x01", "версия не QUIC v1"
        dl = pkt[5]; o = 6 + dl
        sl = pkt[o]; o += 1 + sl
        assert dl in range(8, 21) and sl <= 20, "странные длины CID"
        tl = pkt[o]; o += 1 + tl          # token length (varint, у клиента 0)
        assert tl == 0, "у клиентского Initial должен быть пустой token"
        assert pkt[o] & 0xC0 == 0x40, "длина payload не 2-байтный varint"
        plen = int.from_bytes(pkt[o:o+2], "big") & 0x3FFF; o += 2
        assert o + plen == len(pkt), "поле length не сходится с датаграммой"
        assert len(pkt) >= 1200, "RFC 9000 §14.1: клиентский Initial < 1200 байт"
        return "QUIC Initial ok: %d байт, dcid=%d, length сходится" % (len(pkt), dl)
    assert fb & 0x40, "fixed bit не установлен (1-RTT)"
    assert not first, "первым пакетом обязан идти Initial"
    assert len(pkt) >= 1 + 8 + 1, "слишком короткий 1-RTT"
    return "QUIC 1-RTT ok: %d байт" % len(pkt)

fail = 0
for profile in ("tls", "dns", "sip", "quic"):
    for mode in ("--full", ""):
        args = ["python3", GEN, profile] + ([mode] if mode else [])
        out = subprocess.run(args, capture_output=True, text=True).stdout.strip().split("\n")
        label = "%s/%s" % (profile, mode or "compact")
        assert len(out) == 5, "%s: ожидали 5 пакетов, получили %d" % (label, len(out))
        for i, line in enumerate(out, 1):
            rnd, pkt = parse_line(line)
            try:
                if profile == "tls":  msg = check_tls(pkt)
                elif profile == "dns": msg = check_dns(rnd, pkt)
                elif profile == "sip": msg = check_sip(pkt)
                else:                  msg = check_quic(pkt, first=(i == 1))
                print("  OK  %-14s I%d %4dB  %s" % (label, i, len(pkt) + rnd, msg))
            except AssertionError as e:
                fail += 1
                print("  FAIL %-13s I%d %4dB  %s" % (label, i, len(pkt) + rnd, e))
os.unlink(GEN)
print("\nпровалов:", fail)
sys.exit(1 if fail else 0)
