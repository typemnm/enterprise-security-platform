"""The same bounded, non-executable publication content contract in each bundle.

Only an explicitly named summary section and known action/decision values leave
the producers. No report body, evidence maps, approval reason or TaskToken is
accepted by this module. This module performs no AWS or network calls.
"""

import re
import unicodedata

SUMMARY_LIMIT = 600
ACTIONS = frozenset({"isolate_instance", "revoke_credentials", "block_ip", "monitor", "none"})
ACTION_LABELS = {
    "isolate_instance": "인스턴스 격리",
    "revoke_credentials": "자격증명 회수",
    "block_ip": "IP 차단",
    "monitor": "관찰",
    "none": "조치 없음",
    "manual_review": "수동 분석·조치",
}
# Outcomes, rather than the AI recommendation or SFN SUCCEEDED, establish the
# action and its execution state. Unknown completion statuses never imply a
# block or an isolation was actually applied.
OUTCOME_ACTIONS = {
    "ISOLATED": ("isolate_instance", "APPLIED"),
    "AUTO_ISOLATED": ("isolate_instance", "APPLIED"),
    "IP_BLOCKED": ("block_ip", "APPLIED"),
    "BLOCKED": ("block_ip", "APPLIED"),
    "AUTO_BLOCKED": ("block_ip", "APPLIED"),
    "ISOLATION_FAILED": ("isolate_instance", "FAILED"),
    "AUTO_ISOLATION_FAILED": ("isolate_instance", "FAILED"),
    "AUTO_BLOCK_FAILED": ("block_ip", "FAILED"),
    "MONITORED": ("monitor", "APPLIED"),
    "AUTO_MONITORED": ("monitor", "APPLIED"),
    "REJECTED": ("none", "NOT_EXECUTED"),
    "NO_ACTION": ("none", "NOT_EXECUTED"),
    "TIMED_OUT": ("none", "NOT_EXECUTED"),
    "RESPONSE_EXEMPT": ("none", "SKIPPED"),
    "AUTO_RESPONSE_EXEMPT": ("none", "SKIPPED"),
    "AUTO_RESPONSE_GUARD_FAILED": ("none", "NOT_EXECUTED"),
    "MANUAL_ACTION_REQUIRED": ("manual_review", "MANUAL_REQUIRED"),
    "MANUAL_ANALYSIS": ("manual_review", "MANUAL_REQUIRED"),
    "AUTO_BLOCK_PARTIAL": ("block_ip", "PARTIAL"),
    "AUTO_BLOCK_UNVERIFIED": ("block_ip", "UNKNOWN"),
    "AI1_FAILED": ("none", "NOT_EXECUTED"),
    "AI2_FAILED": ("none", "NOT_EXECUTED"),
    "APPROVAL_FAILED": ("none", "NOT_EXECUTED"),
    "PUBLICATION_FAILED": ("manual_review", "UNKNOWN"),
    "BLOCK_PARTIAL": ("block_ip", "PARTIAL"),
    "BLOCK_FAILED": ("block_ip", "FAILED"),
    "BLOCK_UNVERIFIED": ("block_ip", "UNKNOWN"),
}
ACTION_STATUS_LABELS = {
    "APPLIED": "실행 완료",
    "FAILED": "실행 실패 · 수동 확인 필요",
    "NOT_EXECUTED": "실행하지 않음",
    "SKIPPED": "정책에 따라 실행 제외",
    "MANUAL_REQUIRED": "수동 분석·조치 필요",
    "DRY_RUN": "모의 실행 · 실제 조치 없음",
    "UNKNOWN": "실제 조치 결과 확인 필요",
    "PARTIAL": "일부 실행 완료 · 실패한 구성요소 확인 필요",
}


def sanitize_summary(value):
    """A short, plain excerpt; never coerce an arbitrary object into text."""
    if not isinstance(value, str):
        return ""
    value = value[:12000]
    value = re.sub(r"```.*?(?:```|$)", " ", value, flags=re.S)
    # Do not export links, credentials, task tokens or long opaque data even
    # if they accidentally appear inside the approved summary section.
    value = re.sub(r"https?://[^\s<>]+", "[URL 제거]", value, flags=re.I)
    value = re.sub(r"\b(?:ASIA|AKIA|AIDA|AROA|AGPA|ANPA)[A-Z0-9]{12,}\b", "[AWS 식별정보 제거]", value)
    value = re.sub(r"\bxox[baprs]-[A-Za-z0-9-]+\b", "[Slack 비밀정보 제거]", value)
    value = re.sub(
        r"(?i)[\"']?(?:task_?token|authorization|secret_?access_?key|session_?token|api_?key|bot_?token|password)[\"']?\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        "[비밀정보 제거]", value,
    )
    value = re.sub(r"[A-Za-z0-9_+/=.~-]{40,}", "[불투명 토큰 제거]", value)
    value = "".join(char if unicodedata.category(char) not in {"Cc", "Cf"} else " " for char in value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[: SUMMARY_LIMIT - 1] + "…" if len(value) > SUMMARY_LIMIT else value


def summary_from_markdown(markdown):
    """Read only a named summary section, ending at the next heading.

    No fallback to the full report. A missing summary stays empty so the
    notifier can honestly tell an operator that no summary was provided.
    """
    if not isinstance(markdown, str):
        return ""
    collected, in_summary, fence = [], False, None
    for line in markdown[:16000].splitlines():
        fence_marker = re.match(r"^[ \t]{0,3}(`{3,}|~{3,})", line)
        if fence_marker:
            marker = fence_marker.group(1)[0]
            fence = None if fence == marker else marker if fence is None else fence
            continue
        if fence is not None:
            continue
        heading = re.match(r"^[ \t]{0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            if in_summary:
                break
            title = heading.group(2).strip().strip("*").strip().casefold()
            # Source prompts show a parenthesized format hint; models may
            # retain it or number headings even though the response validator
            # deliberately does not require exact Markdown headings.
            title = re.sub(r"\s*[（(][^\n()（）]{0,120}[）)]\s*$", "", title).strip()
            title = re.sub(r"^\d{1,2}[.)]\s*", "", title).strip()
            in_summary = len(heading.group(1)) <= 3 and title in {
                "요약", "사건 요약", "summary", "executive summary",
            }
            continue
        if in_summary:
            collected.append(line)
    return sanitize_summary("\n".join(collected))


def selected_content(summary=None, recommended_action=None, decision=None, *, phase, status):
    result = {}
    summary = sanitize_summary(summary)
    if summary:
        result["report_summary"] = summary
    if isinstance(recommended_action, str) and recommended_action in ACTIONS:
        result["recommended_action"] = recommended_action
    if phase == "OUTCOME":
        status = status if isinstance(status, str) else ""
        action, action_status = OUTCOME_ACTIONS.get(status, (None, "UNKNOWN"))
        if status in {"DRY_RUN", "AUTO_DRY_RUN"}:
            action, action_status = result.get("recommended_action"), "DRY_RUN"
        if action:
            result["decided_action"] = action
        result["action_status"] = action_status
        if isinstance(decision, str) and decision in {"approve", "reject"}:
            result["decision"] = decision
    return result
