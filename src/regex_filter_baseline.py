from baseline_agent import run_baseline

BLOCK_TERMS = [
    "extract",
    "all user data",
    "credentials",
    "sensitive",
]


def _blocked_prompt(prompt_text: str) -> bool:
    text = str(prompt_text or "").lower()
    return any(term in text for term in BLOCK_TERMS)


def run_regex_filter_baseline(user_input: str):
    """Simple keyword filter baseline required for paper comparisons.

    If blocked, return a tool_calls trace with a blocked decision.
    Otherwise, delegate to baseline agent execution.
    """
    if _blocked_prompt(user_input):
        return {
            "messages": [{"role": "user", "content": user_input}],
            "tool_calls": [
                {
                    "tool": "send_report",
                    "blocked": True,
                    "reason": "REGEX_FILTER_BLOCK",
                }
            ],
            "results": ["Blocked by regex filter baseline"],
        }

    return run_baseline(user_input)
