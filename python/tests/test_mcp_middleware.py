import time
from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_mcp.middleware import extract_token, detect_mode, verify_request
from aip_mcp.error import aip_error_response
from aip_token.error import TokenError
import pytest

def test_extract_token_found():
    headers = {"X-AIP-Token": "some.jwt.token", "Content-Type": "application/json"}
    assert extract_token(headers) == "some.jwt.token"

def test_extract_token_missing():
    headers = {"Content-Type": "application/json"}
    assert extract_token(headers) is None

def test_extract_token_case_insensitive():
    headers = {"x-aip-token": "token123"}
    assert extract_token(headers) == "token123"

def test_detect_compact():
    assert detect_mode("eyJhbGciOiJFZERTQSJ9.payload.sig") == "compact"

def test_detect_chained():
    assert detect_mode("En0KEwoE...") == "chained"

def test_verify_request_success():
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:example.com/agent",
        sub="aip:web:example.com/tool",
        scope=["tool:search"],
        budget_usd=1.0,
        max_depth=0,
        iat=int(time.time()),
        exp=int(time.time()) + 3600,
    )
    token_str = CompactToken.create(claims, kp)
    headers = {"X-AIP-Token": token_str}
    result = verify_request(headers, kp.public_key_bytes(), required_scope="tool:search")
    assert result.claims.iss == "aip:web:example.com/agent"

def test_verify_request_wrong_scope():
    kp = KeyPair.generate()
    claims = AipClaims(
        iss="aip:web:example.com/agent",
        sub="aip:web:example.com/tool",
        scope=["tool:search"],
        budget_usd=None,
        max_depth=0,
        iat=int(time.time()),
        exp=int(time.time()) + 3600,
    )
    token_str = CompactToken.create(claims, kp)
    headers = {"X-AIP-Token": token_str}
    with pytest.raises(TokenError) as exc_info:
        verify_request(headers, kp.public_key_bytes(), required_scope="tool:email")
    assert exc_info.value.code == "aip_scope_insufficient"

def test_verify_request_missing_token():
    kp = KeyPair.generate()
    headers = {"Content-Type": "application/json"}
    with pytest.raises(TokenError) as exc_info:
        verify_request(headers, kp.public_key_bytes(), required_scope="tool:search")
    assert exc_info.value.code == "aip_token_missing"

def test_error_response_format():
    resp = aip_error_response("aip_token_missing", "No AIP token provided", 401)
    assert resp["error"]["code"] == "aip_token_missing"
    assert resp["status"] == 401
