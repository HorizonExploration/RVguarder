from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import platform
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_dumps(payload) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames or ["empty"])
        writer.writeheader()
        if not rows:
            writer.writerow({"empty": ""})
        else:
            writer.writerows(rows)


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def detect_local_ports(ports: Iterable[int], timeout: float = 0.08) -> list[int]:
    reachable: list[int] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex(("127.0.0.1", int(port))) == 0:
                    reachable.append(int(port))
            except OSError:
                continue
    return reachable


def html_escape(text: Any) -> str:
    return html.escape(str(text))


def redact_secret(value: str | None) -> str:
    if not value:
        return ""
    raw = str(value)
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:3]}****{raw[-3:]}"


def first_lines(text: str, limit: int = 3) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()][:limit]


def collect_env_snapshot() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "hostname": socket.gethostname(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME"),
        "cwd": os.getcwd(),
    }


def build_simple_pdf(path: Path, title: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sanitized = [title, ""] + [line.replace("(", "[").replace(")", "]") for line in lines]
    content_lines = ["BT", "/F1 11 Tf", "50 780 Td"]
    first = True
    for line in sanitized:
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if first:
            content_lines.append(f"({escaped}) Tj")
            first = False
        else:
            content_lines.append("0 -16 Td")
            content_lines.append(f"({escaped}) Tj")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("utf-8")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n",
        f"4 0 obj << /Length {len(content)} >> stream\n".encode("utf-8") + content + b"\nendstream endobj\n",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
    ]
    buffer = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(buffer))
        buffer.extend(obj)
    xref_start = len(buffer)
    buffer.extend(f"xref\n0 {len(offsets)}\n".encode("utf-8"))
    buffer.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    buffer.extend(
        f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("utf-8")
    )
    path.write_bytes(bytes(buffer))


class LazyProxy:
    """线程安全的惰性代理 —— 用于延迟初始化非热路径组件。

    首次访问属性时通过 factory 创建真实实例，之后缓存复用。
    使用双重检查锁定保证多线程环境下的安全性和性能。

    Usage::

        rv_engine = LazyProxy(lambda: RuntimeVerificationEngine(window_size=10))
        # 首次访问触发创建
        result = rv_engine.evaluate(trace)
    """

    def __init__(self, factory):
        self._factory = factory
        self._instance = None
        self._lock = threading.Lock()

    def _get(self):
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = self._factory()
        return self._instance

    def __getattr__(self, name):
        return getattr(self._get(), name)

    # ── 容器协议透传（dunder methods 在类型上查找，不走 __getattr__）──

    def __iter__(self):
        return iter(self._get())

    def __getitem__(self, key):
        return self._get()[key]

    def __len__(self):
        return len(self._get())

    def __contains__(self, item):
        return item in self._get()

    def __bool__(self):
        return bool(self._get())

    def __setitem__(self, key, value):
        self._get()[key] = value

    def __delitem__(self, key):
        del self._get()[key]

    def __repr__(self):
        return repr(self._get())
