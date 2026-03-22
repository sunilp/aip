"""Simple policy profiles for Biscuit-based AIP tokens."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class SimplePolicy:
    """A simple policy that generates Datalog checks for Biscuit tokens.

    Budget is expressed in integer cents (Biscuit has no float support).
    """

    tools: list[str] = field(default_factory=list)
    budget_cents: int | None = None
    max_depth: int | None = None
    ttl_seconds: int | None = None

    def to_datalog(self) -> str:
        rules: list[str] = []
        if self.tools:
            tool_list = ", ".join(f'"{t}"' for t in self.tools)
            rules.append(f"check if tool($tool), [{tool_list}].contains($tool);")
        if self.budget_cents is not None:
            rules.append(f"check if budget($b), $b <= {self.budget_cents};")
        if self.max_depth is not None:
            rules.append(f"check if depth($d), $d <= {self.max_depth};")
        if self.ttl_seconds is not None:
            expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=self.ttl_seconds)
            rules.append(
                f'check if time($t), $t <= {expiry.strftime("%Y-%m-%dT%H:%M:%SZ")};'
            )
        return "\n".join(rules)
