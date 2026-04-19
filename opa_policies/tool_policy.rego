package tool_policy

default allow = false

deny_tools := {"delete_all_records", "exfiltrate_secrets"}

allow if {
    input.tool == "read_users"
}

allow if {
    input.tool == "send_report"
    not input.sequence_violation
}

allow if {
    input.tool != "send_report"
    not deny_tools[input.tool]
}
