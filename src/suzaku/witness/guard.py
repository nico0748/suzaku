"""Witness 本番アクセス検知ガード (最重要安全機構)。

Suzaku は本番アクセスを完全にブロックする。許可ホストは以下のみ:

- 文字列リテラル: ``localhost``, ``127.0.0.1``, ``0.0.0.0``, ``::1``
- サフィックス: ``.test``, ``.local``, ``.localhost``, ``.invalid``
- IPv4 RFC1918 帯: 10/8, 172.16/12, 192.168/16, 127/8
- IPv6: ``::1``, IPv4-mapped (``::ffff:127.0.0.1`` 等), Unique Local (``fc00::/7``)

許可帯以外を判定したら :class:`ProductionAccessError` を投げる。

DNS rebinding 対策として、ホスト名はホワイトリストに合致する場合のみ通し、
それ以外は名前解決後の全 IP が許可帯内であることを確認する。
"""

from __future__ import annotations

import ipaddress
import socket

ALLOWED_HOST_LITERALS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
)
ALLOWED_SUFFIXES: tuple[str, ...] = (".test", ".local", ".localhost", ".invalid")
ALLOWED_IPV4_CIDRS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("0.0.0.0/32"),
)
ALLOWED_IPV6_CIDRS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),  # Unique Local
    ipaddress.IPv6Network("fe80::/10"),  # Link-Local
)


class ProductionAccessError(Exception):
    """本番アクセスの試みを検知した際に投げられる例外。

    CLI レイヤはこの例外を捕捉して即時終了し、警告ログを残す。
    """


def _strip_brackets_and_port(host: str) -> str:
    """``[::1]:8080`` や ``host:443`` を ``::1`` / ``host`` に正規化する。"""
    host = host.strip()
    if host.startswith("["):
        # [ipv6]:port
        end = host.find("]")
        if end == -1:
            return host
        return host[1:end]
    # IPv4 / hostname の :port を剥がす (ただし IPv6 (::1) はコロン複数なのでスキップ)
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """文字列を IP として解釈する。8進/16進/decimal/short-form もカバー。"""
    # IPv6 を優先
    try:
        return ipaddress.IPv6Address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(host)
    except ValueError:
        pass
    # decimal / hex の単一数値 (例: "2130706433", "0x7f000001")
    if "." not in host:
        try:
            if host.startswith(("0x", "0X")):
                value = int(host, 16)
            elif host.isdigit():
                value = int(host)
            else:
                value = None
            if value is not None and 0 <= value <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(value)
        except (ValueError, ipaddress.AddressValueError):
            pass
    # short form ("127.1" -> 127.0.0.1) / 8 進混在 ("0177.0.0.1")
    return _parse_dotted_variants(host)


def _parse_dotted_variants(host: str) -> ipaddress.IPv4Address | None:
    """ドット区切り変種 (8進/16進/short form) を IPv4 として解釈する。

    例: ``0177.0.0.1`` (= 127.0.0.1), ``127.1`` (= 127.0.0.1),
        ``0x7f.0.0.1``.
    """
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return None

    nums: list[int] = []
    for raw in parts:
        if not raw:
            return None
        try:
            if raw.startswith(("0x", "0X")):
                nums.append(int(raw, 16))
            elif raw.startswith("0") and len(raw) > 1 and raw.isdigit():
                nums.append(int(raw, 8))
            elif raw.isdigit():
                nums.append(int(raw))
            else:
                return None
        except ValueError:
            return None

    if any(n < 0 for n in nums):
        return None

    # short form: a / a.b / a.b.c / a.b.c.d
    try:
        if len(nums) == 1:
            value = nums[0]
        elif len(nums) == 2:
            a, b = nums
            if a > 0xFF or b > 0xFFFFFF:
                return None
            value = (a << 24) | b
        elif len(nums) == 3:
            a, b, c = nums
            if a > 0xFF or b > 0xFF or c > 0xFFFF:
                return None
            value = (a << 24) | (b << 16) | c
        else:
            a, b, c, d = nums
            if any(x > 0xFF for x in (a, b, c, d)):
                return None
            value = (a << 24) | (b << 16) | (c << 8) | d

        if not 0 <= value <= 0xFFFFFFFF:
            return None
        return ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError):
        return None


def _is_allowed_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in ALLOWED_IPV4_CIDRS)


def _is_allowed_ipv6(ip: ipaddress.IPv6Address) -> bool:
    # IPv4-mapped IPv6 は IPv4 として判定
    if ip.ipv4_mapped is not None:
        return _is_allowed_ipv4(ip.ipv4_mapped)
    return any(ip in net for net in ALLOWED_IPV6_CIDRS)


def _is_allowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return _is_allowed_ipv4(ip)
    return _is_allowed_ipv6(ip)


def _resolve_host(host: str) -> list[str]:
    """ホスト名を IP に解決する (テストで monkeypatch される)。"""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    addrs: set[str] = {str(info[4][0]) for info in infos}
    return list(addrs)


def is_allowed_host(host: str) -> bool:
    """``host`` がホワイトリストに合致するかを判定する。

    Args:
        host: ホスト名 or IP。``[::1]:8080`` や ``host:443`` も受理。

    Returns:
        True なら通す、False なら拒否。
    """
    if not host:
        return False

    normalized = _strip_brackets_and_port(host).lower()
    if not normalized:
        return False

    # 文字列リテラル一致
    if normalized in ALLOWED_HOST_LITERALS:
        return True

    # IP として解釈できればそれで判定 (バイパス表記もここで正規化される)
    ip = _parse_ip(normalized)
    if ip is not None:
        return _is_allowed_ip(ip)

    # ホスト名: 許可サフィックスに合致しない限り解決結果を信用しない
    # (DNS rebinding 対策: attacker.com が一時的に 127.0.0.1 を返しても拒否)
    matches_suffix = any(normalized.endswith(suf) for suf in ALLOWED_SUFFIXES)
    if not matches_suffix:
        return False

    # 許可サフィックスでも、解決先 IP が全て許可帯に入ることを確認
    resolved = _resolve_host(normalized)
    if not resolved:
        # 解決不能だがサフィックスは合致 (例: 未起動の myapp.test) → 許可
        return True
    try:
        resolved_ips = [ipaddress.ip_address(r) for r in resolved]
    except ValueError:
        return False
    return all(_is_allowed_ip(r) for r in resolved_ips)


def enforce_allowed(host: str) -> None:
    """許可ホストでなければ :class:`ProductionAccessError` を投げる。

    Witness の HTTP クライアント / Docker 起動前にこれを呼ぶ。
    """
    if not is_allowed_host(host):
        raise ProductionAccessError(
            f"Production access blocked: host '{host}' is not in the allow-list. "
            "Suzaku only permits local/RFC1918/test domains."
        )
