def strong_provenance_check(trace):
    """
    Blocks if any source tool output can flow into any sink tool.

    Conservative approximation:
    - If read_users appears before send_report -> block.
    """
    tools = [t.get("tool") for t in trace if t.get("tool") and not t.get("blocked")]

    if "read_users" in tools and "send_report" in tools:
        return True

    return False
