"""Herald 追加申請ルートのディスパッチャ (Phase 2-D)。

Phase 1 の GHSA / vendor email に加えて、MITRE CNA-LR / huntr.dev /
JPCERT/CC / Wordfence / Patchstack / HackerOne / Bugcrowd への申請
テンプレートを生成する。

設計方針:
- 既存 :class:`Advisory` を変更しない (後方互換)
- ルート別の追加情報は :class:`RouteContext` に分離
- ルート別の必須フィールドは :class:`RouteError` で検証
- :data:`FORBIDDEN_PHRASES` ガードは全テンプレートで共通
- 実 API への自動送信は **本 Phase でも実装しない** (人間が手動投稿)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from suzaku.herald.email_tmpl import FORBIDDEN_PHRASES, ExtortionLanguageError
from suzaku.herald.ghsa import Advisory, _build_context, _env
from suzaku.models import Route

ROUTES_YAML = Path(__file__).parent / "data" / "routes.yaml"


class RouteError(ValueError):
    """ルート別の必須フィールドが欠けている場合に発生する。"""


@dataclass(frozen=True)
class ContactAttempt:
    """ベンダ通知履歴のエントリ。MITRE 申請時の justification に使う。"""

    attempted_at: datetime
    channel: str  # "email" / "github_issue" / "twitter" / "distros@" など
    response: str  # "no_response" / "acknowledged" / "ignored" / "bounced"
    note: str = ""


@dataclass
class RouteContext:
    """ルート別の補足情報。Advisory の本体は不変に保つ。"""

    # MITRE 用
    vendor_contact_attempts: list[ContactAttempt] = field(default_factory=list)

    # huntr 用
    huntr_package_name: str | None = None
    huntr_package_ecosystem: str | None = None
    huntr_repo_url: str | None = None

    # JPCERT 用
    jpcert_reporter_role: str = "security_researcher"

    # Wordfence / Patchstack 用
    wp_plugin_slug: str | None = None
    wp_active_installs: int | None = None

    # HackerOne / Bugcrowd 用
    program_handle: str | None = None
    asset_identifier: str | None = None


_routes_cache: dict[str, Any] | None = None


def load_routes_meta(path: Path | None = None) -> dict[str, Any]:
    """routes.yaml をロードする (キャッシュあり)。"""
    global _routes_cache
    target = path or ROUTES_YAML
    if _routes_cache is None or path is not None:
        data: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "routes" not in data:
            raise RouteError(f"routes.yaml malformed: {target}")
        _routes_cache = data["routes"]
    assert _routes_cache is not None
    return _routes_cache


def _template_for(route: Route) -> str:
    routes = load_routes_meta()
    entry = routes.get(route.value)
    if not entry or "template" not in entry:
        raise RouteError(f"No template registered for route {route.value!r}")
    return str(entry["template"])


def _validate_route_context(route: Route, ctx: RouteContext) -> None:
    """ルート別の必須フィールドを検証する。"""
    if route == Route.MITRE:
        if not ctx.vendor_contact_attempts:
            raise RouteError(
                "Route 'mitre' requires at least one ContactAttempt in "
                "vendor_contact_attempts (CNA-LR is a last-resort path)."
            )
    elif route == Route.HUNTR:
        if not ctx.huntr_package_name:
            raise RouteError("Route 'huntr' requires huntr_package_name")
        if not ctx.huntr_package_ecosystem:
            raise RouteError("Route 'huntr' requires huntr_package_ecosystem")
    elif route in (Route.WORDFENCE, Route.PATCHSTACK) and not ctx.wp_plugin_slug:
        raise RouteError(
            f"Route '{route.value}' requires wp_plugin_slug (WordPress plugin/theme slug)"
        )
    elif route in (Route.HACKERONE, Route.BUGCROWD) and not ctx.program_handle:
        raise RouteError(
            f"Route '{route.value}' requires program_handle (target program identifier)"
        )
    # JPCERT / GHSA は追加必須フィールド無し


def _route_context_dict(ctx: RouteContext) -> dict[str, Any]:
    return {
        "vendor_contact_attempts": list(ctx.vendor_contact_attempts),
        "huntr_package_name": ctx.huntr_package_name,
        "huntr_package_ecosystem": ctx.huntr_package_ecosystem,
        "huntr_repo_url": ctx.huntr_repo_url,
        "jpcert_reporter_role": ctx.jpcert_reporter_role,
        "wp_plugin_slug": ctx.wp_plugin_slug,
        "wp_active_installs": ctx.wp_active_installs,
        "program_handle": ctx.program_handle,
        "asset_identifier": ctx.asset_identifier,
    }


def render_for_route(
    advisory: Advisory,
    route: Route,
    context: RouteContext | None = None,
) -> str:
    """指定ルート向けのテンプレートをレンダリングする。

    Raises:
        ChecklistError: Advisory の 5 点セットが揃わない場合
        RouteError: ルート別の必須フィールドが欠けている場合
        ExtortionLanguageError: 出力に脅迫的表現が含まれた場合
    """
    ctx = context or RouteContext()
    _validate_route_context(route, ctx)

    template_name = _template_for(route)
    base_context = _build_context(advisory)  # 5 点セット検証 + cvss/cwe 解決
    base_context.update(_route_context_dict(ctx))

    body = _env().get_template(template_name).render(**base_context)

    lowered = body.lower()
    for phrase in FORBIDDEN_PHRASES:
        if phrase in lowered:
            raise ExtortionLanguageError(
                f"Generated route '{route.value}' submission contains forbidden phrase: "
                f"{phrase!r}. Suzaku refuses to emit extortion-style content."
            )
    return body


def list_routes() -> list[tuple[Route, dict[str, Any]]]:
    """同梱ルート一覧を ``(Route, meta)`` で返す。"""
    routes_meta = load_routes_meta()
    out: list[tuple[Route, dict[str, Any]]] = []
    for r in Route:
        meta = routes_meta.get(r.value)
        if meta is not None:
            out.append((r, meta))
    return out
