"""Expected failures while recreating the GAMBIT experiments."""


class GambitError(Exception):
    """Base class for failures that should end an experiment cleanly."""


class InputValidationError(GambitError):
    """An input file does not match the expected historical shape."""


class LLMConfigurationError(GambitError):
    """Online analysis was requested without valid client configuration."""


class LLMResponseError(GambitError):
    """An LLM did not return a valid response within the retry budget."""


class MitreCorpusError(GambitError):
    """A MITRE corpus is malformed or internally inconsistent."""


class ResumeError(GambitError):
    """Existing stage outputs do not match the requested run."""
