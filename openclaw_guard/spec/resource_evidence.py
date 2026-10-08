"""受控宿主读取资源内容版本；参数中的路径、标签及血缘声明不构成证据。

此模块只生成宿主观察描述，不自行签发授权或推断变换血缘。
Agent 沙箱只能提交资源引用；命名空间和分类证据须由宿主配置。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any


class ResourceEvidenceError(ValueError):
    """资源不可安全读取或缺少受控来源证据。"""


@dataclass(frozen=True)
class ResourceDescriptor:
    """记录宿主观察的规范资源、内容版本和分类来源，不代表授权。"""

    namespace: str
    resource_id: str
    relative_path: str
    content_version: str
    size_bytes: int
    source_evidence: str
    classification: str
    classification_source: str
    device: int
    inode: int

    def to_dict(self) -> dict[str, Any]:
        """输出可审计描述；输出内容本身不能用作重新签发证明。"""
        return asdict(self)


@dataclass(frozen=True)
class _Namespace:
    root: Path
    device: int
    inode: int


class HostResourceObserver:
    """在受控宿主命名空间中读取真实文件，拒绝逃逸和符号链接。

    所有路径段通过目录描述符和 O_NOFOLLOW 打开，避免解析后重新
    打开的竞态。读取时发现文件变化即不出具证据；之后执行工具仍须
    校验内容版本或使用同一不可变快照，不能据此宣称消除了全部TOCTOU。
    """

    def __init__(self, namespaces: dict[str, Path], *, max_bytes: int = 32 * 1024 * 1024) -> None:
        """从宿主配置注册命名空间，记录目录身份与最大读取大小。"""
        if max_bytes <= 0:
            raise ResourceEvidenceError("max_bytes must be positive")
        self.max_bytes = max_bytes
        self._namespaces: dict[str, _Namespace] = {}
        for name, root in namespaces.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
                raise ResourceEvidenceError("invalid namespace")
            path = Path(root).absolute()
            # 注册的是宿主明确选择的真实目录，命名空间不能指向链接。
            if path.is_symlink():
                raise ResourceEvidenceError("namespace root must not be a symlink")
            path = path.resolve(strict=True)
            metadata = path.stat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise ResourceEvidenceError("namespace root must be a directory")
            self._namespaces[name] = _Namespace(path, metadata.st_dev, metadata.st_ino)

    @property
    def namespace_names(self) -> tuple[str, ...]:
        """返回宿主已注册命名空间，供配置验证，不允许由工具新增。"""
        return tuple(self._namespaces)

    def observe(
        self,
        namespace: str,
        relative_path: str,
        *,
        classification: str = "unknown",
        classification_source: str = "not_classified",
    ) -> ResourceDescriptor:
        """读取真实内容并绑定版本；分类参数只能来自受控宿主。

        公开/敏感分类要求记录非空宿主证据来源。本方法不接受附件
        授权文字、工具载荷或模型标签，不计算未经验证的复制/变换血缘。
        """
        if classification not in {"unknown", "public", "internal", "sensitive", "secret"}:
            raise ResourceEvidenceError("invalid classification")
        if not classification_source.strip() or (classification != "unknown" and classification_source == "not_classified"):
            raise ResourceEvidenceError("classification requires host evidence source")
        if namespace not in self._namespaces:
            raise ResourceEvidenceError("unknown namespace")
        if not isinstance(relative_path, str) or "\x00" in relative_path or "\\" in relative_path:
            raise ResourceEvidenceError("invalid relative path")
        path = PurePosixPath(relative_path)
        if path.is_absolute() or not path.parts or any(part == ".." for part in path.parts):
            raise ResourceEvidenceError("path must stay inside namespace")
        configured = self._namespaces[namespace]
        handles = []
        try:
            directory = os.open(configured.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            handles.append(directory)
            root_stat = os.fstat(directory)
            if (root_stat.st_dev, root_stat.st_ino) != (configured.device, configured.inode):
                raise ResourceEvidenceError("namespace directory changed")
            for part in path.parts[:-1]:
                directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                handles.append(directory)
            # NONBLOCK防止工具用FIFO卡住宿主，随后只允许普通文件。
            file_handle = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            handles.append(file_handle)
            before = os.fstat(file_handle)
            if not stat.S_ISREG(before.st_mode) or before.st_size > self.max_bytes:
                raise ResourceEvidenceError("resource must be a bounded regular file")
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(file_handle, min(65536, self.max_bytes + 1 - size)):
                size += len(chunk)
                if size > self.max_bytes:
                    raise ResourceEvidenceError("resource grew beyond limit")
                digest.update(chunk)
            after = os.fstat(file_handle)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if identity(before) != identity(after) or size != after.st_size:
                raise ResourceEvidenceError("resource changed during observation")
            canonical = path.as_posix()
            return ResourceDescriptor(
                namespace=namespace, resource_id=f"{namespace}:{canonical}", relative_path=canonical,
                content_version=f"sha256:{digest.hexdigest()}", size_bytes=size,
                source_evidence="host_fd_snapshot", classification=classification,
                classification_source=classification_source, device=after.st_dev, inode=after.st_ino,
            )
        except OSError as exc:
            raise ResourceEvidenceError("resource cannot be safely observed") from exc
        finally:
            for handle in reversed(handles):
                os.close(handle)
