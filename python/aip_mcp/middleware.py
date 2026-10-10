from aip_token.compact import CompactToken
from aip_token.error import TokenError
from aip_token.jwt_chain import JwtChain, detect_format

def extract_token(headers: dict) -> str | None:
    """Extract AIP token from headers. Case-insensitive."""
    for key, value in headers.items():
        if key.lower() == "x-aip-token":
            return value
    return None

def detect_mode(token: str) -> str:
    """Detect the token encoding: "jwt-chain", "compact" (legacy) or "chained" (Biscuit)."""
    fmt = detect_format(token)
    return "chained" if fmt == "biscuit" else fmt

def verify_request(headers: dict, public_key_bytes: bytes, required_scope: str):
    """Verify AIP token from request headers.

    For compact mode: verifies JWT and checks scope.
    For chained mode: verifies Biscuit chain and authorizes tool.

    Returns verified token on success, raises TokenError on failure.
    """
    from aip_mcp import error as err

    token_str = extract_token(headers)
    if not token_str:
        raise TokenError("No AIP token provided", "aip_token_missing")

    mode = detect_mode(token_str)

    if mode == "jwt-chain":
        chain = JwtChain.verify(token_str, bytes(public_key_bytes))
        chain.authorize(required_scope)
        return chain

    if mode == "compact":
        verified = CompactToken.verify(token_str, public_key_bytes)
        if not verified.has_scope(required_scope):
            raise TokenError(
                f"Token does not authorize {required_scope}",
                "aip_scope_insufficient"
            )
        return verified
    else:
        # Chained mode - try to import, may not be available
        try:
            from aip_token.chained import ChainedToken
            # public_key_bytes needs to be exactly 32 bytes for chained
            pk = bytes(public_key_bytes)
            chained = ChainedToken.from_base64(token_str, pk)
            chained.authorize(required_scope, pk)
            return chained
        except ImportError:
            raise TokenError(
                "Chained mode requires biscuit-python",
                "aip_token_malformed"
            )
