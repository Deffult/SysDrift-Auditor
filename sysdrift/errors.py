"""Exception hierarchy for SysDrift Auditor."""


class SysDriftError(Exception):
    """Base class for all expected, user-facing errors."""


class ConfigError(SysDriftError):
    """The scan configuration is invalid."""


class BaselineError(SysDriftError):
    """The baseline file is missing, malformed, or cannot be written."""


class IntegrityError(BaselineError):
    """The baseline failed its integrity / authenticity check."""
