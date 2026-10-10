"""Log parsers. Each parser turns untrusted text into normalized events plus an honest account of what failed."""
from .registry import ParseOptions, ParseResult, parse_text, detect_format, SUPPORTED_FORMATS  # noqa: F401
