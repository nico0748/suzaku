"""Witness Guard — 本番アクセス検知ガードのテスト (最優先・全網羅)。

Suzaku の最重要安全機構。許可ホスト判定のあらゆるバイパスを潰す。

受け入れ基準:
- localhost, 127.0.0.1, *.test, 192.168.x.x は通る
- github.com, 8.8.8.8, example.com はブロック
- IP 表記バイパス (0177.0.0.1, 2130706433 など) は許可ホストへ解決して許可/拒否を判定
- IPv6 ::ffff:7f00:0001 (IPv4-mapped) は許可
- DNS rebinding 対策: ホスト名解決後の IP が ALLOWED_CIDRS 外なら拒否
"""

from __future__ import annotations

import pytest

from suzaku.witness.guard import (
    ProductionAccessError,
    enforce_allowed,
    is_allowed_host,
)


class TestLocalhostAllowed:
    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
        ],
    )
    def test_basic_localhost(self, host: str) -> None:
        assert is_allowed_host(host) is True


class TestAllowedSuffixes:
    @pytest.mark.parametrize(
        "host",
        [
            "service.test",
            "app.local",
            "x.localhost",
            "broken.invalid",
            "deep.nested.test",
        ],
    )
    def test_test_local_suffixes(self, host: str) -> None:
        assert is_allowed_host(host) is True


class TestRFC1918Allowed:
    @pytest.mark.parametrize(
        "host",
        [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.254",
        ],
    )
    def test_rfc1918(self, host: str) -> None:
        assert is_allowed_host(host) is True


class TestPublicHostsBlocked:
    @pytest.mark.parametrize(
        "host",
        [
            "github.com",
            "8.8.8.8",
            "example.com",
            "1.1.1.1",
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",
            "172.32.0.1",  # 172.16/12 の外
            "11.0.0.1",  # 10/8 の外
            "192.169.0.1",  # 192.168/16 の外
        ],
    )
    def test_public_hosts(self, host: str) -> None:
        assert is_allowed_host(host) is False


class TestIPNotationBypass:
    """IP 表記バイパスは正規化して判定する。"""

    @pytest.mark.parametrize(
        "host",
        [
            "0177.0.0.1",  # octal -> 127.0.0.1
            "2130706433",  # decimal -> 127.0.0.1
            "0x7f000001",  # hex -> 127.0.0.1
            "0x7f.0.0.1",  # mixed -> 127.0.0.1
            "127.1",  # short form -> 127.0.0.1
        ],
    )
    def test_loopback_notation_variants_allowed(self, host: str) -> None:
        assert is_allowed_host(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            "0x08080808",  # 8.8.8.8 hex
            "134744072",  # 8.8.8.8 decimal
            "0xa9fea9fe",  # 169.254.169.254 hex (metadata)
        ],
    )
    def test_public_notation_variants_blocked(self, host: str) -> None:
        assert is_allowed_host(host) is False


class TestIPv6:
    def test_ipv4_mapped_loopback_allowed(self) -> None:
        # IPv4-mapped IPv6: ::ffff:127.0.0.1
        assert is_allowed_host("::ffff:7f00:0001") is True
        assert is_allowed_host("::ffff:127.0.0.1") is True

    def test_ipv6_loopback_allowed(self) -> None:
        assert is_allowed_host("::1") is True

    def test_ipv6_unique_local_allowed(self) -> None:
        # fc00::/7 (Unique Local)
        assert is_allowed_host("fc00::1") is True
        assert is_allowed_host("fd12:3456::1") is True

    def test_ipv6_public_blocked(self) -> None:
        # Google DNS over IPv6
        assert is_allowed_host("2001:4860:4860::8888") is False


class TestDNSRebindingProtection:
    """ホスト名を解決後、結果 IP が許可帯外なら拒否する。"""

    def test_evil_host_resolving_to_public_ip_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from suzaku.witness import guard

        def fake_resolve(_host: str) -> list[str]:
            return ["8.8.8.8"]

        monkeypatch.setattr(guard, "_resolve_host", fake_resolve)
        # ホスト名自体がサフィックスに該当しなければ拒否
        assert is_allowed_host("evil.example.com") is False

    def test_evil_host_resolving_to_loopback_blocked_if_not_in_whitelist(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ホスト名がホワイトリストでなければ、解決先が loopback でも拒否。

        DNS rebinding 対策: 明示的に許可された名前以外は信用しない。
        """
        from suzaku.witness import guard

        def fake_resolve(_host: str) -> list[str]:
            return ["127.0.0.1"]

        monkeypatch.setattr(guard, "_resolve_host", fake_resolve)
        # rebind 攻撃: 名前は public ぽいが A レコードが loopback
        assert is_allowed_host("attacker.com") is False

    def test_multi_record_one_public_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """複数 A レコードのうち1つでも public IP があれば拒否。"""
        from suzaku.witness import guard

        def fake_resolve(_host: str) -> list[str]:
            return ["127.0.0.1", "8.8.8.8"]

        monkeypatch.setattr(guard, "_resolve_host", fake_resolve)
        # .test サフィックスでも、解決先に public があれば拒否
        assert is_allowed_host("rebind.test") is False


class TestEnforceAllowed:
    def test_allowed_host_passes(self) -> None:
        # 例外が出なければ OK
        enforce_allowed("127.0.0.1")
        enforce_allowed("localhost")

    def test_blocked_host_raises(self) -> None:
        with pytest.raises(ProductionAccessError) as exc:
            enforce_allowed("github.com")
        assert "github.com" in str(exc.value)

    def test_blocked_includes_reason(self) -> None:
        with pytest.raises(ProductionAccessError):
            enforce_allowed("8.8.8.8")


class TestEdgeCases:
    def test_empty_host_blocked(self) -> None:
        assert is_allowed_host("") is False

    def test_uppercase_localhost_allowed(self) -> None:
        # ホスト名は case-insensitive
        assert is_allowed_host("LOCALHOST") is True
        assert is_allowed_host("App.TEST") is True

    def test_host_with_port_stripped(self) -> None:
        # URL から host:port 形式で入っても判定できること
        assert is_allowed_host("localhost:8080") is True
        assert is_allowed_host("github.com:443") is False

    def test_brackets_ipv6(self) -> None:
        # URL の [::1]:8080 形式
        assert is_allowed_host("[::1]:8080") is True
        assert is_allowed_host("[2001:4860:4860::8888]:443") is False
