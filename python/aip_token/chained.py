"""ChainedToken: Biscuit-backed delegation tokens for AIP.

Bridges AIP's Ed25519 key pairs with biscuit-python to provide
cryptographically attenuated delegation chains.

Block layout follows the canonical encoding in draft-prakash-aip-02
Section 3.4.1, and verification follows the algorithm in Section 4. Both are
normative: an implementation that encodes the same intent differently produces
tokens no other implementation can verify.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from biscuit_auth import (
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    Fact,
    Policy,
    PrivateKey as BiscuitPrivateKey,
    PublicKey as BiscuitPublicKey,
    Rule,
)

from aip_core.crypto import KeyPair
from aip_token.canonical import (
    int_fact,
    str_fact,
    time_check,
    tool_check,
    validate_term,
)
from aip_token.chain_model import Link, authorize_request, verify_links
from aip_token.chain_model import covers as _covers
from aip_token.error import TokenError

# biscuit-python >= 0.4 requires an Algorithm argument for from_bytes();
# older versions do not.  Detect at import time.
try:
    from biscuit_auth import Algorithm as _Algorithm
    _ED25519 = _Algorithm.Ed25519
except ImportError:
    _ED25519 = None  # type: ignore[assignment]


def _biscuit_private_key(keypair: KeyPair) -> BiscuitPrivateKey:
    """Convert an AIP KeyPair's private key to a biscuit PrivateKey."""
    raw = keypair.private_key_bytes()
    if _ED25519 is not None:
        return BiscuitPrivateKey.from_bytes(raw, _ED25519)
    return BiscuitPrivateKey.from_bytes(raw)  # type: ignore[call-arg]


def _biscuit_public_key(raw_bytes: bytes) -> BiscuitPublicKey:
    """Convert raw 32-byte public key bytes to a biscuit PublicKey."""
    if _ED25519 is not None:
        return BiscuitPublicKey.from_bytes(raw_bytes, _ED25519)
    return BiscuitPublicKey.from_bytes(raw_bytes)  # type: ignore[call-arg]



# Canonical block encoding lives in aip_token.canonical so that the chained
# builder and the standalone SimplePolicy renderer cannot drift apart.


def _parse_scopes(source: str) -> set[str] | None:
    """Extract a block's scope patterns from its tool check.

    The check statement is the authoritative declaration, because it is what
    constrains authorization. `right` facts are descriptive metadata and are
    deliberately not trusted here: a block carrying a permissive check and no
    matching facts would otherwise read as declaring nothing.

    Returns None when the block has no tool check, meaning it does not
    constrain scope and inherits its parent's allowlist.
    """
    match = re.search(r"^check if (.*?);\s*$", source, re.M | re.S)
    if not match or "tool($t)" not in match.group(1):
        return None

    scopes: set[str] = set()
    for clause in match.group(1).split(" or "):
        clause = clause.strip()
        if clause == "tool($t)":
            scopes.add("*")
            continue
        contains = re.search(r"\[(.*?)\]\.contains\(\$t\)", clause, re.S)
        if contains:
            scopes.update(re.findall(r'"([^"]*)"', contains.group(1)))
        for prefix in re.findall(r'\$t\.starts_with\("([^"]*)"\)', clause):
            scopes.add(f"{prefix}*")
    return scopes or None


def _parse_int_fact(source: str, name: str) -> int | None:
    match = re.search(rf"^{name}\((-?\d+)\);", source, re.M)
    return int(match.group(1)) if match else None


def _parse_str_fact(source: str, name: str) -> str | None:
    match = re.search(rf'^{name}\("([^"]*)"\);', source, re.M)
    return match.group(1) if match else None


_TIME_CHECK = re.compile(r"^check if time\(\$t\), \$t <= (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ);", re.M)


_SINGLE_STR = ("identity", "delegator", "delegate", "context", "principal")
_SINGLE_INT = ("budget_ceiling", "max_depth")


def _reject_duplicate_facts(source: str, index: int) -> None:
    for name in _SINGLE_STR:
        if len(re.findall(rf'^{name}\("', source, re.M)) > 1:
            raise TokenError.token_malformed(f"block {index} repeats the {name} fact")
    for name in _SINGLE_INT:
        if len(re.findall(rf"^{name}\(-?\d+\);", source, re.M)) > 1:
            raise TokenError.token_malformed(f"block {index} repeats the {name} fact")


def _require_parties(source: str, index: int) -> None:
    required = ("identity",) if index == 0 else ("delegator", "delegate")
    for name in required:
        if not re.search(rf'^{name}\("', source, re.M):
            raise TokenError.token_malformed(f"block {index} has no {name} fact")


def _parse_str_facts(source: str, name: str) -> list[str]:
    return re.findall(rf'^{name}\("([^"]*)"\);', source, re.M)


def _parse_expiry(source: str) -> int | None:
    match = _TIME_CHECK.search(source)
    if not match:
        return None
    stamp = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%SZ")
    return int(stamp.replace(tzinfo=timezone.utc).timestamp())


class ChainedToken:
    """A Biscuit-based chained delegation token.

    Supports creating authority tokens, delegating with attenuation, and
    verifying a chain end to end.
    """

    def __init__(
        self,
        biscuit: Biscuit,
        issuer: str,
        max_depth: int,
        root_pubkey_bytes: bytes,
        depth: int = 0,
    ) -> None:
        self._biscuit = biscuit
        self._issuer = issuer
        self._max_depth = max_depth
        self._root_pubkey_bytes = root_pubkey_bytes
        self._depth = depth
        self._effective: Link | None = None

    # -- accessors ---------------------------------------------------------

    def issuer(self) -> str:
        return self._issuer

    def max_depth(self) -> int:
        return self._max_depth

    def current_depth(self) -> int:
        return self._depth

    def block_count(self) -> int:
        return self._biscuit.block_count()

    def block_source(self, index: int) -> str:
        """Datalog source of one block. Only meaningful after signature verification."""
        return self._biscuit.block_source(index) or ""

    def to_base64(self) -> str:
        return self._biscuit.to_base64()

    # -- minting -----------------------------------------------------------

    @staticmethod
    def create_authority(
        issuer: str,
        scopes: list[str],
        budget_cents: int | None,
        max_depth: int,
        ttl_seconds: int,
        keypair: KeyPair,
        principal: str | None = None,
        domains: list[str] | None = None,
    ) -> ChainedToken:
        """Create a new authority (root) token."""
        if budget_cents is not None and budget_cents < 0:
            raise TokenError("budget ceiling must be non-negative", "budget_exceeded")
        if not scopes:
            raise TokenError.token_malformed("authority declares an empty tools list")
        if domains is not None and not domains:
            raise TokenError.token_malformed("authority declares an empty domains list")

        expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=ttl_seconds)

        facts = str_fact("identity", issuer)
        if principal is not None:
            facts += str_fact("principal", principal)
        for scope in scopes:
            facts += str_fact("right", scope)
        for domain in domains or []:
            facts += str_fact("domain", domain)
        facts += int_fact("max_depth", max_depth)
        if budget_cents is not None:
            facts += int_fact("budget_ceiling", budget_cents)
        if scopes:
            facts += tool_check(scopes)
        facts += time_check(expiry)

        biscuit = BiscuitBuilder(facts).build(_biscuit_private_key(keypair))
        return ChainedToken(biscuit, issuer, max_depth, keypair.public_key_bytes(), depth=0)

    def delegate(
        self,
        delegator: str,
        delegate: str,
        scopes: list[str],
        budget_cents: int | None,
        context: str,
        principal: str | None = None,
        domains: list[str] | None = None,
    ) -> ChainedToken:
        """Append an attenuated delegation block.

        Attenuation is checked here at mint time as a convenience to the
        delegator. It is checked again at verification, because an attacker
        appending a block does not run this code.
        """
        if not context or not context.strip():
            raise TokenError("Context must be non-empty", "token_malformed")

        if self._depth >= self._max_depth:
            raise TokenError("Delegation depth exceeded", "depth_exceeded")

        parent_scopes = self._effective_scopes()
        if parent_scopes is not None:
            widened = [
                s for s in scopes if not any(_covers(p, s) for p in parent_scopes)
            ]
            if widened:
                raise TokenError(
                    f"delegation would widen scope: {', '.join(sorted(widened))}",
                    "scope_insufficient",
                )

        if budget_cents is not None:
            if budget_cents < 0:
                raise TokenError("budget ceiling must be non-negative", "budget_exceeded")
            parent_budget = self._effective_budget()
            if parent_budget is not None and budget_cents > parent_budget:
                raise TokenError(
                    f"delegation would raise budget ceiling from {parent_budget} "
                    f"to {budget_cents}",
                    "budget_exceeded",
                )

        if domains is not None and not domains:
            raise TokenError.token_malformed("delegation declares an empty domains list")
        if domains is not None:
            parent_domains = self._effective_domains()
            if parent_domains is not None:
                widened = sorted(set(domains) - parent_domains)
                if widened:
                    raise TokenError(
                        f"delegation would widen domains: {', '.join(widened)}",
                        "scope_insufficient",
                    )

        block = str_fact("delegator", delegator)
        block += str_fact("delegate", delegate)
        block += str_fact("context", context)
        for domain in domains or []:
            block += str_fact("domain", domain)
        if principal is not None:
            block += str_fact("principal", principal)
        if budget_cents is not None:
            block += int_fact("budget_ceiling", budget_cents)
        if scopes:
            block += tool_check(scopes)

        new_biscuit = self._biscuit.append(BlockBuilder(block))
        return ChainedToken(
            new_biscuit,
            self._issuer,
            self._max_depth,
            self._root_pubkey_bytes,
            depth=self._depth + 1,
        )

    # -- verification (draft-prakash-aip-02 Section 4) ---------------------

    def verify_chain(self, root_public_key_bytes: bytes) -> Biscuit:
        """Verify the chain without evaluating a tool-specific policy.

        Runs V1 (chain integrity), V3 (depth), V4 (structural attenuation
        walk) and V5 (delegation context), and returns the verified Biscuit so
        a caller can run V6 against it.

        This exists for relying parties that must establish what a chain
        conveys on a request that names no tool. An MCP proxy sees
        `initialize` and `tools/list` as well as `tools/call`, and skipping
        verification on those because there is no tool to check would leave
        depth, attenuation and context unenforced for the whole session.

        V2 (root binding) is the caller's responsibility: it supplies the root
        key it resolved for the issuer this chain declares, and MUST confirm
        that the key belongs to that issuer. V7 (revocation) is handled by the
        transport binding.
        """
        # V1: re-verify every block signature from the serialized form. Nothing
        # below may read block content before this succeeds.
        verified = Biscuit.from_base64(
            self._biscuit.to_base64(), _biscuit_public_key(root_public_key_bytes)
        )

        # V3, V4, V5 on the shared link model.
        self._effective = verify_links(self.links(), int(time.time()))

        return verified

    def authorize(
        self, tool: str, root_public_key_bytes: bytes, domain: str | None = None
    ) -> None:
        """Verify the chain and authorize one tool invocation.

        Runs V1, V3, V4, V5 via :meth:`verify_chain`, then V6 (policy
        evaluation) for the named tool.
        """
        verified = self.verify_chain(root_public_key_bytes)

        # V6: policy evaluation. Ambient facts are tool, time and depth only.
        # Supplying a budget fact here would make any budget check evaluate
        # against verifier-chosen data; budget is handled in chain_model.verify_links.
        #
        # The requested tool is the one input to this step that the caller
        # controls, and in an MCP binding it arrives straight from the agent's
        # JSON-RPC params. It is validated and then bound as a Datalog
        # parameter, never interpolated into the source: a tool name that
        # closed its own string could append `allow if true` to this very
        # authorizer and pass any check the token carries.
        validate_term(tool, "tool")

        now = datetime.now(tz=timezone.utc)
        try:
            builder = AuthorizerBuilder(
                f'time({now.strftime("%Y-%m-%dT%H:%M:%SZ")});\n'
                f"depth({self._depth});\n"
            )
            builder.add_fact(Fact("tool({t})", {"t": tool}))
            builder.add_policy(Policy("allow if tool({t})", {"t": tool}))
            builder.build(verified).authorize()
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError(f"insufficient scope: {exc}", "scope_insufficient") from exc

        # V6, structural part: tools are already enforced by the Datalog checks
        # above; domains are facts only, so they are checked here.
        authorize_request(self._effective, tool, domain)

    def _effective_scopes(self) -> set[str] | None:
        """The most recent allowlist declared in the chain, or None if unconstrained.

        The last declaration is the narrowest: every block that declares scopes
        was checked against its parent when it was appended and again in
        chain_model.verify_links, so a later declaration can only be a subset.
        """
        scopes = None
        for i in range(self.block_count()):
            block_scopes = _parse_scopes(self.block_source(i))
            if block_scopes is not None:
                scopes = block_scopes
        return scopes

    def _effective_budget(self) -> int | None:
        """The lowest ceiling declared so far, or None if none is declared."""
        budget = None
        for i in range(self.block_count()):
            block_budget = _parse_int_fact(self.block_source(i), "budget_ceiling")
            if block_budget is not None:
                budget = block_budget if budget is None else min(budget, block_budget)
        return budget

    def _effective_domains(self) -> set[str] | None:
        domains = None
        for i in range(self.block_count()):
            block_domains = _parse_str_facts(self.block_source(i), "domain")
            if block_domains:
                domains = set(block_domains)
        return domains

    # Invariant the parsers rely on: each dimension is enforced in exactly one
    # place. Tools and time are enforced by the Datalog checks in every block.
    # Domains and budget are enforced only by the parsed facts, which
    # verify_links subset-checks. So hiding a fact from the parser can only
    # fall back to inheriting the parent's value, never widen it. Biscuit
    # prints string literals unescaped, so honest minting depends on
    # validate_term (via str_fact) rejecting terms that could break out.
    def links(self) -> list[Link]:
        """Parse the chain into the encoding-neutral link model.

        Only meaningful after V1. Block 0 has no delegate in this encoding,
        and delegator/delegate in later blocks are asserted, not
        authenticated, because biscuit appends them under ephemeral keys
        (draft-prakash-aip-02 Section 5.2).
        """
        out: list[Link] = []
        for index in range(self.block_count()):
            source = self.block_source(index)
            _reject_duplicate_facts(source, index)
            _require_parties(source, index)
            scopes = _parse_scopes(source)
            domains = _parse_str_facts(source, "domain")
            out.append(Link(
                issuer=(_parse_str_fact(source, "identity") if index == 0
                        else _parse_str_fact(source, "delegator")) or "",
                delegate=None if index == 0 else _parse_str_fact(source, "delegate"),
                tools=frozenset(scopes) if scopes is not None else None,
                domains=frozenset(domains) if domains else None,
                budget_cents=_parse_int_fact(source, "budget_ceiling"),
                expiry=_parse_expiry(source),
                context=None if index == 0 else _parse_str_fact(source, "context"),
                principal=_parse_str_fact(source, "principal"),
                max_depth=_parse_int_fact(source, "max_depth"),
            ))
        return out

    @property
    def effective(self) -> Link:
        if self._effective is None:
            raise TokenError.token_malformed("chain has not been verified")
        return self._effective

    # -- deserialization ---------------------------------------------------

    @staticmethod
    def from_base64(s: str, root_public_key_bytes: bytes) -> ChainedToken:
        """Deserialize and verify a token against the root public key (V1)."""
        biscuit = Biscuit.from_base64(s, _biscuit_public_key(root_public_key_bytes))
        source = biscuit.block_source(0) or ""
        issuer = _parse_str_fact(source, "identity") or "unknown"
        max_depth = _parse_int_fact(source, "max_depth")
        return ChainedToken(
            biscuit,
            issuer,
            max_depth if max_depth is not None else 3,
            root_public_key_bytes,
            depth=biscuit.block_count() - 1,
        )
