class AipError(Exception):
    pass


class InvalidIdentifier(AipError):
    pass


class InvalidDocument(AipError):
    pass


class SignatureInvalid(AipError):
    pass


class DocumentExpired(AipError):
    pass


class VersionUnsupported(AipError):
    pass
