class ShadowPocError(Exception):
    """Base error for the trusted PoC implementation."""


class ContractError(ShadowPocError):
    """An untrusted input failed its strict contract."""


class ConfigurationError(ShadowPocError):
    """A trusted configuration is missing, malformed, or inconsistent."""


class EvidenceIntegrityError(ShadowPocError):
    """An evidence record or chain failed validation."""
