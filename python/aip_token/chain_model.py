"""Encoding-neutral delegation chain model (draft-prakash-aip-02 Sections 3-4).

Every encoding parses a verified token into a list of Link objects and hands
it to verify_links. Steps V3, V4 and V5 live here and nowhere else, and they
run on structured values, never on policy text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from aip_token.error import TokenError


@dataclass(frozen=True)
class Link:
    """One link of a delegation chain. Index 0 is the authority link."""

    issuer: str
    delegate: str | None = None
    tools: frozenset[str] | None = None
    domains: frozenset[str] | None = None
    budget_cents: int | None = None
    expiry: int | None = None
    context: str | None = None
    principal: str | None = None
    max_depth: int | None = None


def covers(pattern: str, value: str) -> bool:
    """Does an ancestor pattern permit a descendant value?

    A wildcard permits any value it prefixes. A specific value never widens to
    a wildcard, because "tool:*" does not start with "tool:search".
    """
    if pattern == value or pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return False


def _widened_tools(parent: frozenset[str], child: frozenset[str]) -> list[str]:
    return sorted(c for c in child if not any(covers(p, c) for p in parent))


def verify_links(links: list[Link], now: int) -> Link:
    """V3 (depth), V4 (structural attenuation walk), V5 (delegation context).

    Returns the effective capabilities at the leaf: each dimension is the
    nearest declared value walking back from the leaf. Raises TokenError with
    the -01/-02 error codes on the first violation.
    """
    if not links:
        raise TokenError.token_malformed("chain has no links")

    root = links[0]
    if root.tools is None:
        raise TokenError.token_malformed("authority link declares no tools")
    if root.expiry is None:
        raise TokenError.token_malformed("authority link declares no expiry")
    if root.max_depth is None or root.max_depth < 0:
        raise TokenError.token_malformed("authority link declares no max_depth")

    for index, link in enumerate(links):
        if link.tools == frozenset():
            raise TokenError.token_malformed(f"link {index} declares an empty tools list")
        if link.domains == frozenset():
            raise TokenError.token_malformed(f"link {index} declares an empty domains list")

    # V3
    if len(links) - 1 > root.max_depth:
        raise TokenError.depth_exceeded()

    if root.budget_cents is not None and root.budget_cents < 0:
        raise TokenError.budget_exceeded()
    if root.expiry < now:
        raise TokenError.token_expired()

    effective = root
    for index, link in enumerate(links[1:], start=1):
        if link.max_depth is not None:
            raise TokenError.token_malformed(f"delegation link {index} declares max_depth")

        # V5
        if not link.context or not link.context.strip():
            raise TokenError.token_malformed(f"delegation link {index} has no context")

        # V4, one dimension at a time
        tools = effective.tools
        if link.tools is not None:
            widened = _widened_tools(effective.tools, link.tools)
            if widened:
                raise TokenError.scope_insufficient(
                    f"link {index} widens tools: {', '.join(widened)}"
                )
            tools = link.tools

        domains = effective.domains
        if link.domains is not None:
            if effective.domains is not None:
                widened = sorted(link.domains - effective.domains)
                if widened:
                    raise TokenError.scope_insufficient(
                        f"link {index} widens domains: {', '.join(widened)}"
                    )
            domains = link.domains

        budget = effective.budget_cents
        if link.budget_cents is not None:
            if link.budget_cents < 0:
                raise TokenError.budget_exceeded()
            if budget is not None and link.budget_cents > budget:
                raise TokenError.budget_exceeded()
            budget = link.budget_cents

        expiry = effective.expiry
        if link.expiry is not None:
            if link.expiry > effective.expiry or link.expiry < now:
                raise TokenError.token_expired()
            expiry = link.expiry

        principal = effective.principal
        if link.principal is not None:
            if principal is not None and link.principal != principal:
                raise TokenError.token_malformed(
                    f"link {index} substitutes the principal: {principal} became {link.principal}"
                )
            principal = link.principal

        effective = replace(
            link,
            tools=tools,
            domains=domains,
            budget_cents=budget,
            expiry=expiry,
            principal=principal,
            max_depth=root.max_depth,
        )

    return effective


def authorize_request(effective: Link, tool: str, domain: str | None = None) -> None:
    """The structural part of V6: is this request inside the leaf's authority?"""
    if effective.tools is None or not any(covers(p, tool) for p in effective.tools):
        raise TokenError.scope_insufficient(tool)
    if domain is not None and effective.domains is not None and domain not in effective.domains:
        raise TokenError.scope_insufficient(domain)
