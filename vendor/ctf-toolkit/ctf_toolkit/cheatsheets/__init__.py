"""Cheat sheets for various attack techniques."""

from .sqli import SQLI_CHEATSHEET
from .xss import XSS_CHEATSHEET
from .cmdi import CMDI_CHEATSHEET
from .ssrf import SSRF_CHEATSHEET
from .xxe import XXE_CHEATSHEET
from .lfi import LFI_CHEATSHEET
from .ssti import SSTI_CHEATSHEET

__all__ = [
    "SQLI_CHEATSHEET",
    "XSS_CHEATSHEET",
    "CMDI_CHEATSHEET",
    "SSRF_CHEATSHEET",
    "XXE_CHEATSHEET",
    "LFI_CHEATSHEET",
    "SSTI_CHEATSHEET",
]
