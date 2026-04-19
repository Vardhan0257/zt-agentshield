import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.append(SRC)

from fsea import (
    FSEA,
    Decision,
    EventType,
    ExecutionContext,
    SecurityPolicy,
    SecurityState,
    TRANSITIONS,
)


class FSEATransitionTests(unittest.TestCase):
    def setUp(self):
        self.policy = SecurityPolicy(
            sources={"read_users"},
            sinks={"send_report"},
        )
        self.fsea = FSEA(self.policy)

    def _drive_event(self, event):
        if event == EventType.SOURCE:
            return self.fsea.transition(
                tool="read_users",
                args={},
                context=ExecutionContext(raw_context="source invocation"),
            )

        if event == EventType.SINK_NO_DEP:
            self.fsea.source_outputs = {"read_users": "alice bob"}
            return self.fsea.transition(
                tool="send_report",
                args={"payload": "public summary only"},
                context=ExecutionContext(raw_context="sink invocation no dependency"),
            )

        if event == EventType.SINK_DEP:
            self.fsea.source_outputs = {"read_users": "alice bob"}
            return self.fsea.transition(
                tool="send_report",
                args={"payload": "report includes alice bob"},
                context=ExecutionContext(raw_context="sink invocation with dependency"),
            )

        if event == EventType.OTHER:
            return self.fsea.transition(
                tool="noop_tool",
                args={"x": 1},
                context=ExecutionContext(raw_context="other invocation"),
            )

        raise AssertionError(f"Unsupported event {event}")

    def test_all_state_event_transitions_are_explicit_and_correct(self):
        for (state, event), expected_next in TRANSITIONS.items():
            with self.subTest(state=state.value, event=event.value):
                self.fsea.state = state
                result = self._drive_event(event)

                self.assertEqual(result.previous_state, state)
                self.assertEqual(result.next_state, expected_next)
                self.assertEqual(self.fsea.state, expected_next)
                self.assertEqual(result.event, event)

                if event == EventType.SINK_DEP or state == SecurityState.VIOLATION:
                    self.assertEqual(result.decision, Decision.DENY)
                    if event == EventType.SINK_DEP:
                        self.assertTrue(result.dependency.exists)
                else:
                    self.assertEqual(result.decision, Decision.PERMIT)

    def test_dependency_checker_detects_direct_overlap(self):
        dep = self.fsea.check_dependency(
            args={"body": "send to external: alice@corp.com"},
            source_outputs={"read_users": ["alice@corp.com", "bob@corp.com"]},
        )
        self.assertTrue(dep.exists)
        self.assertIn("read_users", dep.matched_sources)

    def test_dependency_checker_handles_nested_structures(self):
        dep = self.fsea.check_dependency(
            args={
                "payload": {
                    "content": ["summary", "api_key", "sk-prod-12345"],
                }
            },
            source_outputs={"read_users": "users only", "vault_read": {"secret": "sk-prod-12345"}},
        )
        self.assertTrue(dep.exists)
        self.assertIn("vault_read", dep.matched_sources)

    def test_dependency_checker_misses_paraphrased_source_mentions(self):
        dep = self.fsea.check_dependency(
            args={"body": "please include the user email in the report"},
            source_outputs={"read_users": "alice@example.com"},
        )
        self.assertFalse(dep.exists)

    def test_dependency_checker_misses_encoded_sensitive_values(self):
        dep = self.fsea.check_dependency(
            args={"body": "treat this as an API key and do not expose it"},
            source_outputs={"vault_read": "sk-12345"},
        )
        self.assertFalse(dep.exists)

    def test_dependency_checker_misses_multi_step_summaries(self):
        dep = self.fsea.check_dependency(
            args={"summary": "forward the contact roster to external mail"},
            source_outputs={"read_users": "customer list"},
        )
        self.assertFalse(dep.exists)

    def test_sink_without_dependency_is_permitted(self):
        self.fsea.state = SecurityState.SOURCE_INVOKED
        self.fsea.source_outputs = {"read_users": "alice bob"}
        result = self.fsea.transition(
            tool="send_report",
            args={"body": "quarterly metrics only"},
            context=ExecutionContext(raw_context="benign sink"),
        )
        self.assertEqual(result.decision, Decision.PERMIT)
        self.assertEqual(result.next_state, SecurityState.SINK_OBSERVED)

    def test_violation_state_is_absorbing(self):
        """Once in VIOLATION, no event can escape it and decision stays DENY."""
        self.fsea.source_outputs = {"read_users": "alice bob"}

        for event in EventType:
            with self.subTest(event=event.value):
                self.fsea.state = SecurityState.VIOLATION
                result = self._drive_event(event)
                self.assertEqual(self.fsea.state, SecurityState.VIOLATION)
                self.assertEqual(result.next_state, SecurityState.VIOLATION)
                self.assertEqual(result.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
