"""削除行 -> VariantRule 変換。

戦略 (最小実装):
1. 削除行を関数呼び出し境界 (``;``, 改行) で分割
2. 文字列リテラルを ``"..."`` に置換、識別子のうち単一文字変数を ``\\w+`` に
3. 既知の危険 API (eval, system, ...) を含む行を優先採用
4. 追加行 (修正後) は ``must_not_contain`` に転写

CWE allow-list (``herald/data/cwe.json``) 外の CVE はルールを生成しない。
"""

from __future__ import annotations

import hashlib
import re

from suzaku.herald.checklist import load_cwe_database
from suzaku.lineage.models import (
    DEFAULT_VARIANT_SEVERITY,
    CVERecord,
    PatchHunk,
    VariantRule,
)

# 危険 API ヒント (Compass の danger_funcs と部分重複だが優先抽出用)
DANGER_KEYWORDS: tuple[str, ...] = (
    "eval", "exec", "system", "popen", "Runtime.exec",
    "unserialize", "pickle.loads", "yaml.load", "marshal.loads",
    "shell_exec", "passthru", "child_process",
    "ObjectInputStream", "DocumentBuilder",
    "fetch", "urlopen", "request", "redirect",
    "strcpy", "strcat", "sprintf", "memcpy", "gets",
)

_STRING_RE = re.compile(r"\"[^\"]*\"|'[^']*'")
_PAREN_ARGS_RE = re.compile(r"\\\([^()]*\\\)")
_STRING_PLACEHOLDER = "__SUZAKU_STR__"

# 既知のスキップ対象 (純 whitespace / comment / brace のみ)
_NOISE_LINE_RE = re.compile(r"^[\s\}\{\)\(\[\];]*$|^[\s]*//|^[\s]*#")


def _normalize_line(line: str) -> str:
    """行を grep 用 regex に正規化する。

    - 文字列リテラル ``"..."`` を ``"[^"]*"`` に置換 (差異を吸収)
    - 関数呼出引数 ``(...)`` を ``([^)]*)`` に置換 (引数名差異を吸収)
    - 残りは ``re.escape`` でエスケープ
    """
    stripped = line.strip()
    if not stripped:
        return ""
    # 文字列リテラルをプレースホルダに退避してから escape
    work = _STRING_RE.sub(_STRING_PLACEHOLDER, stripped)
    escaped = re.escape(work)
    # プレースホルダを文字列リテラル用 regex に戻す
    escaped = escaped.replace(re.escape(_STRING_PLACEHOLDER), r'"[^"]*"')
    # 関数引数 \(...\) の中身を [^)]* に置換
    escaped = _PAREN_ARGS_RE.sub(r"\\([^)]*\\)", escaped)
    # whitespace を \s+ に
    escaped = re.sub(r"(\\\ )+", r"\\s+", escaped)
    return escaped


def _looks_relevant(line: str) -> bool:
    if _NOISE_LINE_RE.match(line):
        return False
    lower = line.lower()
    return any(kw.lower() in lower for kw in DANGER_KEYWORDS) or len(line.strip()) >= 12


def _line_score(line: str) -> int:
    """危険キーワード一致数 + 長さで優先度を付ける。"""
    lower = line.lower()
    score = sum(1 for kw in DANGER_KEYWORDS if kw.lower() in lower)
    return score * 100 + min(len(line.strip()), 200)


def _rule_id(cve_id: str, index: int) -> str:
    return f"lineage_{cve_id}_{index:03d}"


# sanitization の典型語 (mitigation pattern)
_MITIGATION_HINTS: tuple[str, ...] = (
    "validate", "sanitize", "escape", "is_allowed", "is_safe",
    "allowlist", "allow_list", "allowed_host", "verify",
    "encode", "quote", "normalize", "realpath", "abspath",
    "html.escape", "url.parse", "url.quote", "path.normalize",
)
_IDENT_RE = re.compile(r"[A-Za-z_][\w\.]*")


def _added_to_must_not_contain(added_lines: list[str]) -> str | None:
    """追加行から must_not_contain を生成する。

    Sanitization の典型ヒント (validate/sanitize/escape/is_allowed/...) を
    含む新規 identifier を拾う。文字列リテラル + DANGER_KEYWORDS も併用。
    """
    keywords: list[str] = []
    for line in added_lines:
        if _NOISE_LINE_RE.match(line):
            continue
        stripped = line.strip()
        if len(stripped) < 6:
            continue
        # mitigation hint を含む identifier を拾う
        for ident in _IDENT_RE.findall(stripped):
            lower = ident.lower()
            if any(hint in lower for hint in _MITIGATION_HINTS):
                keywords.append(re.escape(ident))
        # 文字列リテラル全体を抽出
        for m in _STRING_RE.findall(stripped):
            if len(m) >= 6:
                keywords.append(re.escape(m[1:-1]))
        # API ヒント (元の脆弱関数が修正後にも残る場合の note)
        for kw in DANGER_KEYWORDS:
            if kw in stripped:
                keywords.append(re.escape(kw))
    if not keywords:
        return None
    # 重複排除
    uniq = list(dict.fromkeys(keywords))
    return "|".join(uniq[:8])


def hunks_to_rules(
    cve: CVERecord,
    hunks: list[PatchHunk],
    *,
    max_rules: int = 5,
) -> list[VariantRule]:
    """``deleted_lines`` から VariantRule を生成する。"""
    allowed_cwes = set(load_cwe_database().keys())
    matched_cwes = [c for c in cve.cwe if c in allowed_cwes]
    if not matched_cwes:
        return []
    primary_cwe = matched_cwes[0]

    candidates: list[tuple[int, PatchHunk, str]] = []
    for hunk in hunks:
        for raw in hunk.deleted_lines:
            if not _looks_relevant(raw):
                continue
            normalized = _normalize_line(raw)
            if not normalized:
                continue
            candidates.append((_line_score(raw), hunk, normalized))

    candidates.sort(key=lambda t: -t[0])

    rules: list[VariantRule] = []
    seen_signatures: set[str] = set()
    for hunk, _score_group in [(h, s) for s, h, _ in candidates[: max_rules * 4]]:  # noqa: B007
        pass  # 後段のループで使うので別経路

    for score, hunk, pattern in candidates:
        if len(rules) >= max_rules:
            break
        sig = hashlib.sha256(pattern.encode("utf-8")).hexdigest()[:12]
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)
        mnc = _added_to_must_not_contain(hunk.added_lines)
        rules.append(
            VariantRule(
                rule_id=_rule_id(cve.cve_id, len(rules) + 1),
                derived_from_cve=cve.cve_id,
                cwe=primary_cwe,
                severity=DEFAULT_VARIANT_SEVERITY,
                language=hunk.language if hunk.language != "unknown" else "any",
                grep=pattern,
                must_not_contain=mnc,
                source_commit=hunk.commit_url,
                rationale=(
                    f"Derived from {cve.cve_id} ({primary_cwe}) patch deletion "
                    f"in {hunk.file_path}. Suzaku variant scan candidate, "
                    f"likelihood score={score}."
                ),
            )
        )
    return rules


__all__ = [
    "DANGER_KEYWORDS",
    "hunks_to_rules",
]
