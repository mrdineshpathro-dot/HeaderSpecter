"""HeaderSpecter — HTTP Security Header Analyzer & Security Posture Scanner.

HeaderSpecter is a defensive security utility: it inspects HTTP/HTTPS response
headers, normalizes and analyzes them, scores the target's security posture and
produces actionable hardening guidance in a number of report formats.

Created by Mr Dinesh Pathro — https://buymeacoffee.com/mrdineshpathro
"""

from __future__ import annotations

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "APP_NAME",
    "TAGLINE",
    "AUTHOR",
    "AUTHOR_URL",
    "PROJECT_URL",
]

__version__ = "1.0.0"
__author__ = "Mr Dinesh Pathro"
__license__ = "MIT"

APP_NAME = "HeaderSpecter"
TAGLINE = "HTTP Security Header Analyzer & Security Posture Scanner"
AUTHOR = "Mr Dinesh Pathro"
AUTHOR_URL = "https://buymeacoffee.com/mrdineshpathro"
PROJECT_URL = "https://github.com/mrdineshpathro-dot/HeaderSpecter"
