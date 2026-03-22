"""Token error types for the AIP token package."""

from __future__ import annotations


class TokenError(Exception):
    """Base error for AIP token operations."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code

    def error_code(self) -> str:
        return self.code

    # -- convenience constructors ------------------------------------------

    @classmethod
    def token_missing(cls) -> TokenError:
        return cls("token is missing", "token_missing")

    @classmethod
    def token_malformed(cls, detail: str = "") -> TokenError:
        msg = "token is malformed"
        if detail:
            msg = f"{msg}: {detail}"
        return cls(msg, "token_malformed")

    @classmethod
    def signature_invalid(cls) -> TokenError:
        return cls("signature is invalid", "signature_invalid")

    @classmethod
    def identity_unresolvable(cls, identity: str = "") -> TokenError:
        msg = "identity cannot be resolved"
        if identity:
            msg = f"{msg}: {identity}"
        return cls(msg, "identity_unresolvable")

    @classmethod
    def token_expired(cls) -> TokenError:
        return cls("token has expired", "token_expired")

    @classmethod
    def scope_insufficient(cls, scope: str = "") -> TokenError:
        msg = "insufficient scope"
        if scope:
            msg = f"{msg}: {scope}"
        return cls(msg, "scope_insufficient")

    @classmethod
    def budget_exceeded(cls) -> TokenError:
        return cls("budget ceiling exceeded", "budget_exceeded")

    @classmethod
    def depth_exceeded(cls) -> TokenError:
        return cls("delegation depth exceeded", "depth_exceeded")

    @classmethod
    def key_revoked(cls) -> TokenError:
        return cls("signing key has been revoked", "key_revoked")
