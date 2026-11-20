"""Receiver-side authorization. Default deny: own org only, R4+ needs a human.

The hub applies the same accept rule as a convenience, but the security
boundary is here, in the agent that executes: a compromised hub cannot
make an agent run a task its own policy refuses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .capabilities import Capability

ALLOW, BLOCK, APPROVAL = "allow", "block", "approval"


@dataclass
class AgentPolicy:
    org: str
    accept_orgs: List[str] = field(default_factory=list)
    accept_agents: List[str] = field(default_factory=list)
    approval_threshold: int = 4

    def __post_init__(self):
        if not self.accept_orgs:
            self.accept_orgs = [self.org]

    def accepts(self, sender: Dict[str, Any]) -> bool:
        return ("*" in self.accept_orgs
                or sender.get("org") in self.accept_orgs
                or sender.get("agent_id") in self.accept_agents)

    def decide(self, sender: Dict[str, Any], cap: Optional[Capability]) -> Tuple[str, str]:
        if cap is None:
            return BLOCK, "unknown-capability"
        if not self.accepts(sender):
            return BLOCK, "sender-not-accepted"
        if cap.risk >= self.approval_threshold:
            return APPROVAL, f"risk-R{cap.risk}-requires-approval"
        return ALLOW, "accepted"

    def card_accepts(self) -> Dict[str, List[str]]:
        return {"orgs": list(self.accept_orgs), "agents": list(self.accept_agents)}


def card_accepts(card: Dict[str, Any], sender: Dict[str, Any]) -> bool:
    accepts = card.get("accepts") or {}
    orgs = accepts.get("orgs") or [card.get("org")]
    return ("*" in orgs or sender.get("org") in orgs
            or sender.get("agent_id") in (accepts.get("agents") or []))


def visible_to(card: Dict[str, Any], viewer: Dict[str, Any]) -> bool:
    visibility = card.get("visibility", "org")
    if visibility == "public":
        return True
    if visibility == "org":
        return card.get("org") == viewer.get("org")
    return False
