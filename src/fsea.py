from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Set
import re


class SecurityState(str, Enum):
    CLEAN = "CLEAN"
    SOURCE_INVOKED = "SOURCE_INVOKED"
    PROPAGATING = "PROPAGATING"
    SINK_OBSERVED = "SINK_OBSERVED"
    VIOLATION = "VIOLATION"


class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"


class EventType(str, Enum):
    SOURCE = "SOURCE"
    SINK_NO_DEP = "SINK_NO_DEP"
    SINK_DEP = "SINK_DEP"
    OTHER = "OTHER"


@dataclass(frozen=True)
class SecurityPolicy:
    sources: Set[str]
    sinks: Set[str]


@dataclass
class ExecutionContext:
    actor_id: str = "agent_primary"
    raw_context: str = ""


@dataclass
class DependencyResult:
    exists: bool
    matched_sources: List[str] = field(default_factory=list)
    matched_fragments: List[str] = field(default_factory=list)


@dataclass
class TransitionResult:
    decision: Decision
    previous_state: SecurityState
    next_state: SecurityState
    event: EventType
    dependency: DependencyResult


# Explicit transition function: (state, event) -> next_state.
TRANSITIONS: Dict[tuple[SecurityState, EventType], SecurityState] = {
    (SecurityState.CLEAN, EventType.SOURCE): SecurityState.SOURCE_INVOKED,
    (SecurityState.CLEAN, EventType.SINK_NO_DEP): SecurityState.SINK_OBSERVED,
    (SecurityState.CLEAN, EventType.SINK_DEP): SecurityState.VIOLATION,
    (SecurityState.CLEAN, EventType.OTHER): SecurityState.CLEAN,

    (SecurityState.SOURCE_INVOKED, EventType.SOURCE): SecurityState.SOURCE_INVOKED,
    (SecurityState.SOURCE_INVOKED, EventType.SINK_NO_DEP): SecurityState.SINK_OBSERVED,
    (SecurityState.SOURCE_INVOKED, EventType.SINK_DEP): SecurityState.VIOLATION,
    (SecurityState.SOURCE_INVOKED, EventType.OTHER): SecurityState.PROPAGATING,

    (SecurityState.PROPAGATING, EventType.SOURCE): SecurityState.SOURCE_INVOKED,
    (SecurityState.PROPAGATING, EventType.SINK_NO_DEP): SecurityState.SINK_OBSERVED,
    (SecurityState.PROPAGATING, EventType.SINK_DEP): SecurityState.VIOLATION,
    (SecurityState.PROPAGATING, EventType.OTHER): SecurityState.PROPAGATING,

    (SecurityState.SINK_OBSERVED, EventType.SOURCE): SecurityState.SOURCE_INVOKED,
    (SecurityState.SINK_OBSERVED, EventType.SINK_NO_DEP): SecurityState.SINK_OBSERVED,
    (SecurityState.SINK_OBSERVED, EventType.SINK_DEP): SecurityState.VIOLATION,
    (SecurityState.SINK_OBSERVED, EventType.OTHER): SecurityState.SINK_OBSERVED,

    (SecurityState.VIOLATION, EventType.SOURCE): SecurityState.VIOLATION,
    (SecurityState.VIOLATION, EventType.SINK_NO_DEP): SecurityState.VIOLATION,
    (SecurityState.VIOLATION, EventType.SINK_DEP): SecurityState.VIOLATION,
    (SecurityState.VIOLATION, EventType.OTHER): SecurityState.VIOLATION,
}


class FSEA:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.state = SecurityState.CLEAN
        self.source_outputs: Dict[str, Any] = {}
        self.live_sources: Set[str] = set()

    def reset(self) -> None:
        self.state = SecurityState.CLEAN
        self.source_outputs = {}
        self.live_sources = set()

    def record_source_output(self, tool: str, output: Any) -> None:
        if tool in self.policy.sources:
            self.source_outputs[tool] = output

    def transition(
        self,
        tool: str,
        args: Dict[str, Any] | None,
        context: ExecutionContext,
    ) -> TransitionResult:
        args = args or {}
        previous = self.state

        if tool in self.policy.sources:
            event = EventType.SOURCE
            dependency = DependencyResult(False)
            self.live_sources.add(tool)
        elif tool in self.policy.sinks:
            dependency = self.check_dependency(args, self.source_outputs)
            event = EventType.SINK_DEP if dependency.exists else EventType.SINK_NO_DEP
        else:
            dependency = DependencyResult(False)
            event = EventType.OTHER

        next_state = TRANSITIONS[(previous, event)]
        self.state = next_state
        decision = (
            Decision.DENY
            if previous == SecurityState.VIOLATION or next_state == SecurityState.VIOLATION
            else Decision.PERMIT
        )

        return TransitionResult(
            decision=decision,
            previous_state=previous,
            next_state=next_state,
            event=event,
            dependency=dependency,
        )

    def check_dependency(
        self,
        args: Dict[str, Any],
        source_outputs: Dict[str, Any],
    ) -> DependencyResult:
        arg_text = " ".join(self._flatten_text_values(args)).lower()
        matched_sources: List[str] = []
        matched_fragments: List[str] = []

        if not arg_text.strip() or not source_outputs:
            return DependencyResult(False)

        arg_tokens = set(self._tokens(arg_text))

        for source_tool, output in source_outputs.items():
            source_text = " ".join(self._flatten_text_values(output)).lower()
            if not source_text.strip():
                continue

            # Pass 1: direct substring overlap using longer source fragments.
            fragments = [frag for frag in self._split_fragments(source_text) if len(frag) >= 8]
            direct_hits = [frag for frag in fragments if frag in arg_text]
            if direct_hits:
                matched_sources.append(source_tool)
                matched_fragments.extend(direct_hits[:3])
                continue

            # Pass 2: token overlap to catch light transformations.
            source_tokens = set(self._tokens(source_text))
            overlap = sorted(source_tokens & arg_tokens)
            high_signal_overlap = [
                tok for tok in overlap
                if "@" in tok or "." in tok or len(tok) >= 12
            ]
            if high_signal_overlap:
                matched_sources.append(source_tool)
                matched_fragments.extend(high_signal_overlap[:5])
            elif len(overlap) >= 3:
                matched_sources.append(source_tool)
                matched_fragments.extend(overlap[:5])

        exists = len(matched_sources) > 0
        return DependencyResult(
            exists=exists,
            matched_sources=matched_sources,
            matched_fragments=matched_fragments,
        )

    def _flatten_text_values(self, value: Any) -> Iterable[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, (int, float, bool)):
            return [str(value)]
        if isinstance(value, dict):
            out: List[str] = []
            for v in value.values():
                out.extend(self._flatten_text_values(v))
            return out
        if isinstance(value, (list, tuple, set)):
            out = []
            for v in value:
                out.extend(self._flatten_text_values(v))
            return out
        return [str(value)]

    def _tokens(self, text: str) -> List[str]:
        return [tok for tok in re.split(r"[^a-z0-9_@.-]+", text) if len(tok) >= 3]

    def _split_fragments(self, text: str) -> List[str]:
        return [frag.strip() for frag in re.split(r"[\n,;]+", text) if frag.strip()]
