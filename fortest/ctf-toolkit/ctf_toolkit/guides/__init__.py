"""Learning guides module for CTF Toolkit.

This module provides educational content for various attack types including:
- Step-by-step checklists
- Detection patterns
- Technique explanations
- WAF bypass methods
- CTF tips
"""

from typing import Optional

# Import all guides
from .sqli import SQLI_GUIDE
from .xss import XSS_GUIDE
from .cmdi import CMDI_GUIDE
from .ssrf import SSRF_GUIDE
from .xxe import XXE_GUIDE
from .lfi import LFI_GUIDE
from .ssti import SSTI_GUIDE
from .bruteforce import BRUTEFORCE_GUIDE

# Guide registry
GUIDES_REGISTRY = {
    "sqli": SQLI_GUIDE,
    "xss": XSS_GUIDE,
    "cmdi": CMDI_GUIDE,
    "ssrf": SSRF_GUIDE,
    "xxe": XXE_GUIDE,
    "lfi": LFI_GUIDE,
    "ssti": SSTI_GUIDE,
    "bruteforce": BRUTEFORCE_GUIDE,
}

# Attack type aliases
ATTACK_ALIASES = {
    "sql": "sqli",
    "sql-injection": "sqli",
    "sqlinjection": "sqli",
    "cross-site-scripting": "xss",
    "command-injection": "cmdi",
    "cmd": "cmdi",
    "os-command": "cmdi",
    "server-side-request-forgery": "ssrf",
    "xml-external-entity": "xxe",
    "local-file-inclusion": "lfi",
    "path-traversal": "lfi",
    "directory-traversal": "lfi",
    "server-side-template-injection": "ssti",
    "template-injection": "ssti",
    "brute": "bruteforce",
    "brute-force": "bruteforce",
    "bf": "bruteforce",
    "password-attack": "bruteforce",
    "directory-bruteforce": "bruteforce",
    "fuzzing": "bruteforce",
}


def get_available_guides() -> list[str]:
    """Get list of available guide types."""
    return list(GUIDES_REGISTRY.keys())


def resolve_attack_type(attack_type: str) -> str:
    """Resolve attack type alias to canonical name."""
    attack_type = attack_type.lower().strip()
    return ATTACK_ALIASES.get(attack_type, attack_type)


def get_guide(attack_type: str) -> Optional[dict]:
    """
    Get complete guide for an attack type.

    Args:
        attack_type: Attack type (sqli, xss, cmdi, ssrf, xxe, lfi, ssti)

    Returns:
        Guide dictionary or None if not found
    """
    attack_type = resolve_attack_type(attack_type)
    return GUIDES_REGISTRY.get(attack_type)


def get_guide_overview(attack_type: str) -> Optional[dict]:
    """
    Get overview section of a guide.

    Returns:
        Dict with title, severity, difficulty, overview, impact
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    return {
        "attack_type": guide["attack_type"],
        "title": guide["title"],
        "severity": guide["severity"],
        "difficulty": guide["difficulty"],
        "overview": guide["overview"],
        "impact": guide.get("impact", []),
    }


def get_techniques(
    attack_type: str,
    technique: Optional[str] = None,
    difficulty: Optional[str] = None
) -> Optional[dict]:
    """
    Get techniques from a guide.

    Args:
        attack_type: Attack type
        technique: Specific technique name (optional)
        difficulty: Filter by difficulty level (optional)

    Returns:
        Dict of techniques or single technique
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    techniques = guide.get("techniques", {})

    if technique:
        return techniques.get(technique)

    if difficulty:
        return {
            k: v for k, v in techniques.items()
            if v.get("difficulty") == difficulty
        }

    return techniques


def get_checklist(attack_type: str) -> Optional[list[dict]]:
    """
    Get checklist for an attack type.

    Args:
        attack_type: Attack type

    Returns:
        List of checklist items
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    return guide.get("checklist", [])


def get_detection_patterns(
    attack_type: str,
    db_type: Optional[str] = None,
    show_examples: bool = False
) -> Optional[list[dict]]:
    """
    Get detection patterns for an attack type.

    Args:
        attack_type: Attack type
        db_type: Filter by database type (for SQLi)
        show_examples: Include example responses

    Returns:
        List of detection patterns
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    patterns = guide.get("detection_patterns", [])

    if db_type:
        patterns = [
            p for p in patterns
            if p.get("db_specific") == db_type or p.get("db_specific") is None
        ]

    if not show_examples:
        # Remove example_response field
        patterns = [
            {k: v for k, v in p.items() if k != "example_response"}
            for p in patterns
        ]

    return patterns


def get_waf_bypass(attack_type: str) -> Optional[list[dict]]:
    """
    Get WAF bypass techniques for an attack type.

    Args:
        attack_type: Attack type

    Returns:
        List of WAF bypass techniques
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    return guide.get("waf_bypass", [])


def get_ctf_tips(attack_type: str) -> Optional[list[str]]:
    """
    Get CTF tips for an attack type.

    Args:
        attack_type: Attack type

    Returns:
        List of CTF tips
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    return guide.get("ctf_tips", [])


def get_quick_reference(attack_type: str) -> Optional[dict]:
    """
    Get quick reference card for an attack type.

    Returns a condensed view with:
    - Top 5 payloads
    - Top 3 detection patterns
    - Key CTF tips

    Args:
        attack_type: Attack type

    Returns:
        Quick reference dictionary
    """
    guide = get_guide(attack_type)
    if not guide:
        return None

    # Get top payloads from techniques
    top_payloads = []
    for tech_name, tech_data in guide.get("techniques", {}).items():
        for payload in tech_data.get("payloads", [])[:2]:
            top_payloads.append({
                "technique": tech_name,
                "payload": payload.get("payload"),
                "purpose": payload.get("purpose"),
            })
        if len(top_payloads) >= 5:
            break

    # Get high confidence detection patterns
    patterns = guide.get("detection_patterns", [])
    high_confidence = [p for p in patterns if p.get("confidence") == "high"][:3]
    if len(high_confidence) < 3:
        high_confidence.extend([p for p in patterns if p.get("confidence") != "high"][:3 - len(high_confidence)])

    return {
        "attack_type": guide["attack_type"],
        "title": guide["title"],
        "severity": guide["severity"],
        "top_payloads": top_payloads[:5],
        "detection_patterns": high_confidence[:3],
        "ctf_tips": guide.get("ctf_tips", [])[:5],
        "key_techniques": list(guide.get("techniques", {}).keys())[:4],
    }


def list_all_guides() -> list[dict]:
    """
    Get summary of all available guides.

    Returns:
        List of guide summaries
    """
    summaries = []
    for attack_type, guide in GUIDES_REGISTRY.items():
        summaries.append({
            "attack_type": attack_type,
            "title": guide["title"],
            "severity": guide["severity"],
            "difficulty": guide["difficulty"],
            "technique_count": len(guide.get("techniques", {})),
            "checklist_steps": len(guide.get("checklist", [])),
        })
    return summaries


__all__ = [
    "GUIDES_REGISTRY",
    "get_available_guides",
    "get_guide",
    "get_guide_overview",
    "get_techniques",
    "get_checklist",
    "get_detection_patterns",
    "get_waf_bypass",
    "get_ctf_tips",
    "get_quick_reference",
    "list_all_guides",
    "resolve_attack_type",
]
