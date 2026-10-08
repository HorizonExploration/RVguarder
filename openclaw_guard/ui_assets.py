"""校验并交付已构建的公开前端资源，拒绝运行时状态与隐含链接。"""
from __future__ import annotations

from pathlib import Path
import re
import shutil

ALLOWED_SUFFIXES = {".html", ".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2"}


def stage_ui_assets(source: Path, destination: Path) -> list[str]:
    """只复制经index引用校验的静态资源；构建前须运行frontend/npm run build。"""
    source, destination = Path(source), Path(destination)
    index = source / "index.html"
    if not index.is_file() or index.is_symlink():
        raise FileNotFoundError("Frontend build missing: run npm run build in frontend/ before building the backend wheel")
    files = [p for p in sorted(source.rglob("*")) if p.is_file()]
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("frontend assets must not contain symlinks")
    allowed = [p for p in files if p.suffix.lower() in ALLOWED_SUFFIXES and not any(
        part.startswith(".") for part in p.relative_to(source).parts)]
    included = {p.relative_to(source).as_posix() for p in allowed}
    references = re.findall(r'(?:src|href)=["\'](/assets/[^"\']+)["\']', index.read_text(encoding="utf-8"))
    if not references or any(ref.lstrip("/").split("?")[0] not in included for ref in references):
        raise ValueError("frontend index references missing or unsupported assets")
    if destination.resolve() == source.resolve():
        raise ValueError("asset staging must use a separate directory")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for path in allowed:
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    return sorted(included)
