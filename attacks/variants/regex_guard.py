SUSPICIOUS_KEYWORDS = [
    "extract",
    "sensitive",
    "confidential",
    "all user data",
]


def regex_guard(prompt):
    prompt_lower = str(prompt).lower()
    return any(keyword in prompt_lower for keyword in SUSPICIOUS_KEYWORDS)
