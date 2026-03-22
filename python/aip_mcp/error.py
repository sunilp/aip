def aip_error_response(code: str, message: str, status: int) -> dict:
    return {
        "error": {"code": code, "message": message},
        "status": status,
    }

def token_missing():
    return aip_error_response("aip_token_missing", "No AIP token provided", 401)

def token_malformed(detail: str):
    return aip_error_response("aip_token_malformed", detail, 401)

def signature_invalid():
    return aip_error_response("aip_signature_invalid", "Signature verification failed", 401)

def token_expired():
    return aip_error_response("aip_token_expired", "Token has expired", 401)

def scope_insufficient(scope: str):
    return aip_error_response("aip_scope_insufficient", f"Token does not authorize {scope}", 403)
