"""JWT chain encoding (draft-prakash-aip-02 Section 5.1).

A chain is a sequence of JWS compact links joined with "~". Link 0 is signed by
the issuer's root key. Every later link is signed by the key the previous link
named in its cnf claim, and carries prev, the SHA-256 of the previous link as
transmitted. That makes each delegator's record authenticated, which the
Biscuit encoding does not provide.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aip_core.crypto import KeyPair
from aip_token.chain_model import Link, authorize_request, verify_links
from aip_token.error import TokenError

LINK_TYP = "aip-link+jwt"
LEGACY_TYP = "aip+jwt"
SEPARATOR = "~"
MEDIA_TYPE = "application/aip-chain+jwt"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _prev_hash(segment: str) -> str:
    return _b64url(hashlib.sha256(segment.encode("ascii")).digest())


def holder_jwk(public_key_bytes: bytes) -> dict:
    """RFC 8037 OKP JWK for an Ed25519 public key, as carried in cnf."""
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public_key_bytes)}


def _holder_key(claims: dict) -> bytes:
    cnf = claims.get("cnf")
    jwk_ = cnf.get("jwk") if isinstance(cnf, dict) else None
    if (
        not isinstance(jwk_, dict)
        or jwk_.get("kty") != "OKP"
        or jwk_.get("crv") != "Ed25519"
        or not isinstance(jwk_.get("x"), str)
    ):
        raise TokenError.token_malformed("cnf must carry an Ed25519 OKP jwk")
    try:
        key = _b64url_decode(jwk_["x"])
    except Exception as exc:
        raise TokenError.token_malformed(f"cnf jwk is not base64url: {exc}") from exc
    if len(key) != 32:
        raise TokenError.token_malformed("cnf jwk is not a 32-byte Ed25519 key")
    return key


def _sign(claims: dict, keypair: KeyPair) -> str:
    return jwt.encode(claims, keypair._private_key, algorithm="EdDSA", headers={"typ": LINK_TYP})


def _header(segment: str) -> dict:
    try:
        return jwt.get_unverified_header(segment)
    except jwt.PyJWTError as exc:
        raise TokenError.token_malformed(str(exc)) from exc


def _verify_segment(segment: str, public_key_bytes: bytes) -> dict:
    """V1 for one link: header pinned, signature checked against the given key."""
    header = _header(segment)
    if header.get("alg") != "EdDSA" or header.get("typ") != LINK_TYP:
        raise TokenError.signature_invalid()
    try:
        return jwt.decode(
            segment,
            Ed25519PublicKey.from_public_bytes(public_key_bytes),
            algorithms=["EdDSA"],
            # Expiry and the other time claims are checked structurally in V4,
            # so that they produce the draft's error codes in one place.
            options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
        )
    except jwt.InvalidSignatureError as exc:
        raise TokenError.signature_invalid() from exc
    except jwt.PyJWTError as exc:
        raise TokenError.token_malformed(str(exc)) from exc


def _str_set(claims: dict, name: str) -> frozenset[str] | None:
    value = claims.get(name)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise TokenError.token_malformed(f"{name} must be an array of strings")
    return frozenset(value)


def _int(claims: dict, name: str) -> int | None:
    value = claims.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise TokenError.token_malformed(f"{name} must be an integer")
    return value


def _str(claims: dict, name: str) -> str | None:
    value = claims.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TokenError.token_malformed(f"{name} must be a string")
    return value


def _to_link(claims: dict) -> Link:
    issuer = _str(claims, "iss")
    if issuer is None or _str(claims, "sub") is None:
        raise TokenError.token_malformed("link must carry iss and sub")
    return Link(
        issuer=issuer,
        delegate=_str(claims, "sub"),
        tools=_str_set(claims, "aip_tools"),
        domains=_str_set(claims, "aip_domains"),
        budget_cents=_int(claims, "aip_budget_cents"),
        expiry=_int(claims, "exp"),
        context=_str(claims, "aip_ctx"),
        principal=_str(claims, "aip_principal"),
        max_depth=_int(claims, "aip_max_depth"),
    )


def _optional(claims: dict, **values: Any) -> dict:
    for name, value in values.items():
        if value is not None:
            claims[name] = sorted(value) if isinstance(value, (list, set, frozenset, tuple)) else value
    return claims


class JwtChain:
    """A JWT-encoded AIP delegation chain."""

    def __init__(self, segments: list[str], claims: list[dict], links: list[Link]) -> None:
        self._segments = segments
        self._claims = claims
        self._links = links
        self._effective: Link | None = None

    # -- accessors ---------------------------------------------------------

    @property
    def links(self) -> list[Link]:
        return list(self._links)

    @property
    def effective(self) -> Link:
        if self._effective is None:
            raise TokenError.token_malformed("chain has not been verified")
        return self._effective

    def issuer(self) -> str:
        return self._links[0].issuer

    def depth(self) -> int:
        return len(self._links) - 1

    def leaf_delegate(self) -> str | None:
        return self._links[-1].delegate

    def serialize(self) -> str:
        return SEPARATOR.join(self._segments)

    # -- minting -----------------------------------------------------------

    @staticmethod
    def create_root(
        *,
        issuer: str,
        delegate: str,
        tools: list[str],
        max_depth: int,
        ttl_seconds: int,
        issuer_keypair: KeyPair,
        holder_public_key: bytes,
        budget_cents: int | None = None,
        domains: list[str] | None = None,
        principal: str | None = None,
        anchor: dict | None = None,
        now: int | None = None,
    ) -> JwtChain:
        """Mint the authority link. The holder key is the delegate's public key."""
        now = int(time.time()) if now is None else now
        claims = {
            "iss": issuer,
            "sub": delegate,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_urlsafe(16),
            "aip_tools": sorted(tools),
            "aip_max_depth": max_depth,
            "cnf": {"jwk": holder_jwk(holder_public_key)},
        }
        _optional(claims, aip_domains=domains, aip_budget_cents=budget_cents,
                  aip_principal=principal, aip_anchor=anchor)
        link = _to_link(claims)
        verify_links([link], now)
        return JwtChain([_sign(claims, issuer_keypair)], [claims], [link])

    def append(
        self,
        *,
        holder_keypair: KeyPair,
        delegate: str,
        next_holder_public_key: bytes,
        context: str,
        tools: list[str] | None = None,
        domains: list[str] | None = None,
        budget_cents: int | None = None,
        ttl_seconds: int | None = None,
        principal: str | None = None,
        now: int | None = None,
    ) -> JwtChain:
        """Append a delegation link signed by the current holder.

        Attenuation is checked here as a convenience to the delegator, and
        again at verification, because an attacker forging a link does not
        run this code.
        """
        now = int(time.time()) if now is None else now
        if holder_keypair.public_key_bytes() != _holder_key(self._claims[-1]):
            raise TokenError.signature_invalid()

        claims = {
            "iss": self._links[-1].delegate,
            "sub": delegate,
            "iat": now,
            "jti": secrets.token_urlsafe(16),
            "prev": _prev_hash(self._segments[-1]),
            "aip_ctx": context,
            "cnf": {"jwk": holder_jwk(next_holder_public_key)},
        }
        _optional(claims, exp=None if ttl_seconds is None else now + ttl_seconds,
                  aip_tools=tools, aip_domains=domains, aip_budget_cents=budget_cents,
                  aip_principal=principal)
        link = _to_link(claims)
        verify_links(self._links + [link], now)
        return JwtChain(
            self._segments + [_sign(claims, holder_keypair)],
            self._claims + [claims],
            self._links + [link],
        )

    # -- verification (draft-prakash-aip-02 Section 4) ---------------------

    @staticmethod
    def verify(token: str, root_public_key_bytes: bytes, now: int | None = None) -> JwtChain:
        """V1, then V3-V5 on the link model.

        V2 (root binding) is the caller's: it supplies the root key it resolved
        for the issuer this chain declares, and MUST confirm the key belongs to
        that issuer. V7 is handled by the transport binding.
        """
        if not token:
            raise TokenError.token_missing()
        now = int(time.time()) if now is None else now
        segments = token.split(SEPARATOR)
        if any(not s for s in segments):
            raise TokenError.token_malformed("empty link in chain")

        if len(segments) == 1 and _header(segments[0]).get("typ") == LEGACY_TYP:
            return JwtChain._verify_legacy(segments[0], root_public_key_bytes, now)

        claims: list[dict] = []
        key = root_public_key_bytes
        for index, segment in enumerate(segments):
            link_claims = _verify_segment(segment, key)
            if index > 0:
                if link_claims.get("prev") != _prev_hash(segments[index - 1]):
                    raise TokenError.signature_invalid()
                if link_claims.get("iss") != claims[index - 1].get("sub"):
                    raise TokenError.signature_invalid()
            key = _holder_key(link_claims)
            claims.append(link_claims)

        chain = JwtChain(segments, claims, [_to_link(c) for c in claims])
        chain._effective = verify_links(chain._links, now)
        return chain

    @staticmethod
    def _verify_legacy(segment: str, root_public_key_bytes: bytes, now: int) -> JwtChain:
        """Accept a -01 compact token as a one-link chain. Deprecated in -02.

        CompactToken.verify does V1 (and rejects an expired token itself); the
        claims are then mapped onto the link model so V3-V6 are shared.
        """
        from aip_token.compact import CompactToken

        claims = CompactToken.verify(segment, root_public_key_bytes).claims
        link = Link(
            issuer=claims.iss,
            delegate=claims.sub,
            tools=frozenset(claims.scope),
            budget_cents=None if claims.budget_usd is None else round(claims.budget_usd * 100),
            expiry=claims.exp,
            max_depth=claims.max_depth,
        )
        chain = JwtChain([segment], [claims.model_dump()], [link])
        chain._effective = verify_links([link], now)
        return chain

    def authorize(self, tool: str, domain: str | None = None) -> None:
        """V6 for the JWT encoding: the request must fall inside the leaf's authority."""
        authorize_request(self.effective, tool, domain)


def detect_format(token: str) -> str:
    """Which encoding is this token? "jwt-chain", "compact" (legacy) or "biscuit".

    Biscuit tokens are base64url protobuf and never start with "eyJ", the
    base64url of '{"'. A JWS header is read without verification only to
    choose the verifier; nothing in it is trusted.
    """
    if not token.startswith("eyJ"):
        return "biscuit"
    if SEPARATOR in token:
        return "jwt-chain"
    try:
        typ = jwt.get_unverified_header(token).get("typ")
    except jwt.PyJWTError:
        return "compact"
    return "jwt-chain" if typ == LINK_TYP else "compact"
