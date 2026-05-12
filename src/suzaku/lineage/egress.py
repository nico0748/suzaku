"""Lineage 専用の egress allow-list ガード。

Phase 1 Witness Guard は ``localhost`` / RFC1918 / ``*.test`` 以外を遮断する。
Lineage は読み取り専用の公開 API (NVD / GitHub) を呼ぶ必要があるため、
**独立した allow-list** をここに置く。Witness Reproducer の挙動は変更しない。

DNS rebinding 対策 / IP バイパス検知のロジックは Witness Guard と同じ
``is_allowed_host`` を **拒否補助** に活用する (allow-list を素通りした後、
public IP かどうかを別途検査する)。
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

import yaml

ALLOWED_HOSTS_YAML = Path(__file__).parent / "data" / "allowed_hosts.yaml"


class LineageEgressError(RuntimeError):
    """allow-list 外の egress 試行を検知した場合に発生。"""


def _load_allowed() -> frozenset[str]:
    data = yaml.safe_load(ALLOWED_HOSTS_YAML.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return frozenset()
    hosts = data.get("read_only_egress", [])
    if not isinstance(hosts, list):
        return frozenset()
    return frozenset(str(h).lower() for h in hosts)


_CACHE: frozenset[str] | None = None


def allowed_hosts() -> frozenset[str]:
    global _CACHE
    if _CACHE is None:
        _CACHE = _load_allowed()
    return _CACHE


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    addrs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            addrs.append(ipaddress.ip_address(str(info[4][0])))
        except ValueError:
            continue
    return addrs


def is_allowed_egress(host: str) -> bool:
    """``host`` が Lineage の読み取り専用 allow-list に該当するか。"""
    if not host:
        return False
    normalized = host.strip().lower()
    if normalized.count(":") == 1:
        normalized = normalized.split(":", 1)[0]
    return normalized in allowed_hosts()


def assert_allowed(host: str) -> None:
    """allow-list 外なら :class:`LineageEgressError` を投げる。"""
    if not is_allowed_egress(host):
        raise LineageEgressError(
            f"Lineage egress to {host!r} is not in the allow-list. "
            f"Allowed: {sorted(allowed_hosts())}"
        )


def reset_cache() -> None:
    """テスト用: YAML を再読込みする。"""
    global _CACHE
    _CACHE = None


__all__ = [
    "ALLOWED_HOSTS_YAML",
    "LineageEgressError",
    "allowed_hosts",
    "assert_allowed",
    "is_allowed_egress",
    "reset_cache",
]
