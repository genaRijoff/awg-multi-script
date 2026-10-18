"""assets.py — файлы панели (index.html, app.js, icons.js) для Mini App и веб-панели.

Раньше каждое открытие панели заново качало ~550 КБ без сжатия. Теперь:
  • сжатие gzip — один раз на версию файла (в памяти), не на каждый запрос;
  • в index.html адреса скриптов несут отпечаток содержимого (app.js?v=…):
    по такому адресу браузер держит файл у себя, пока не выйдет новая версия;
  • index.html и скрипт без отпечатка — с ETag: повторное открытие — ответ 304.
Содержимое панели не секретно (открытый код), поэтому кэш браузера ей не
вредит; «private» — не для общих прокси.
"""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
from typing import Callable

from aiohttp import web

STATIC = Path(__file__).with_name("webapp")
SCRIPTS = ("app.js", "icons.js")
TYPES = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
IMMUTABLE = "private, max-age=31536000, immutable"
REVALIDATE = "no-cache"           # хранить можно, но каждый раз сверять ETag


class _File:
    __slots__ = ("key", "raw", "gz", "tag")

    def __init__(self, raw: bytes, key: object) -> None:
        self.key, self.raw = key, raw
        self.gz = gzip.compress(raw, 9, mtime=0)
        self.tag = hashlib.sha256(raw).hexdigest()[:16]


class Assets:
    """Файлы панели в памяти: перечитываются, только если файл на диске сменился.
    index_fix — правка index.html под свой сервер (веб-панель меняет скрипт
    Telegram на свой web.js)."""

    def __init__(self, index_fix: Callable[[str], str] | None = None, root: Path = STATIC) -> None:
        self.root, self.index_fix = root, index_fix
        self._files: dict[str, _File] = {}

    def _script(self, name: str) -> _File:
        path = self.root / name
        key = path.stat().st_mtime_ns
        f = self._files.get(name)
        if f is None or f.key != key:
            f = self._files[name] = _File(path.read_bytes(), key)
        return f

    def _index(self) -> _File:
        path = self.root / "index.html"
        tags = {s: self._script(s).tag for s in SCRIPTS}
        key = (path.stat().st_mtime_ns, tuple(tags.values()))
        f = self._files.get("index.html")
        if f is None or f.key != key:
            html = path.read_text(encoding="utf-8")
            if self.index_fix:
                html = self.index_fix(html)
            # Отпечаток версии — в адрес скрипта: новая версия — новый адрес
            for s, tag in tags.items():
                html = html.replace(f'<script src="{s}"></script>', f'<script src="{s}?v={tag}"></script>')
            f = self._files["index.html"] = _File(html.encode("utf-8"), key)
        return f

    def response(self, request: web.Request, name: str) -> web.Response:
        if name == "index.html":
            f = self._index()
        elif name in SCRIPTS:
            f = self._script(name)
        else:
            raise web.HTTPNotFound()
        etag = f'"{f.tag}"'
        versioned = name in SCRIPTS and request.query.get("v") == f.tag
        headers = {"ETag": etag, "Cache-Control": IMMUTABLE if versioned else REVALIDATE,
                   "Vary": "Accept-Encoding", "Content-Type": TYPES[Path(name).suffix]}
        if etag in [t.strip() for t in request.headers.get("If-None-Match", "").split(",")]:
            return web.Response(status=304, headers=headers)
        if "gzip" in request.headers.get("Accept-Encoding", ""):
            headers["Content-Encoding"] = "gzip"
            return web.Response(body=f.gz, headers=headers)
        return web.Response(body=f.raw, headers=headers)
