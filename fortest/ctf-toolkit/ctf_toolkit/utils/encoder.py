"""Encoding and decoding utilities for CTF Toolkit."""

import base64
import urllib.parse
import binascii
import html
import json
from typing import Optional


class Encoder:
    """Utility class for various encoding/decoding operations."""

    # Base64
    @staticmethod
    def base64_encode(data: str) -> str:
        """Encode string to base64."""
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(data: str) -> str:
        """Decode base64 to string."""
        # Handle padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.b64decode(data).decode()

    # URL Encoding
    @staticmethod
    def url_encode(data: str, safe: str = "") -> str:
        """URL encode a string."""
        return urllib.parse.quote(data, safe=safe)

    @staticmethod
    def url_decode(data: str) -> str:
        """URL decode a string."""
        return urllib.parse.unquote(data)

    @staticmethod
    def double_url_encode(data: str) -> str:
        """Double URL encode a string (for WAF bypass)."""
        first = urllib.parse.quote(data, safe="")
        return urllib.parse.quote(first, safe="")

    # Hex
    @staticmethod
    def hex_encode(data: str) -> str:
        """Encode string to hex."""
        return data.encode().hex()

    @staticmethod
    def hex_decode(data: str) -> str:
        """Decode hex to string."""
        return bytes.fromhex(data).decode()

    @staticmethod
    def hex_encode_sql(data: str) -> str:
        """Encode string to SQL hex format (0x...)."""
        return "0x" + data.encode().hex()

    # HTML
    @staticmethod
    def html_encode(data: str) -> str:
        """HTML encode a string."""
        return html.escape(data)

    @staticmethod
    def html_decode(data: str) -> str:
        """HTML decode a string."""
        return html.unescape(data)

    @staticmethod
    def html_entity_encode(data: str) -> str:
        """Encode to HTML numeric entities."""
        return "".join(f"&#{ord(c)};" for c in data)

    # Unicode
    @staticmethod
    def unicode_encode(data: str) -> str:
        """Encode to Unicode escape sequences (\\uXXXX)."""
        return "".join(f"\\u{ord(c):04x}" for c in data)

    @staticmethod
    def unicode_decode(data: str) -> str:
        """Decode Unicode escape sequences."""
        return data.encode().decode("unicode_escape")

    # Binary
    @staticmethod
    def binary_encode(data: str) -> str:
        """Encode string to binary."""
        return " ".join(format(ord(c), "08b") for c in data)

    @staticmethod
    def binary_decode(data: str) -> str:
        """Decode binary to string."""
        binary_values = data.split()
        return "".join(chr(int(b, 2)) for b in binary_values)

    # ROT13
    @staticmethod
    def rot13(data: str) -> str:
        """Apply ROT13 encoding/decoding."""
        result = []
        for char in data:
            if "a" <= char <= "z":
                result.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= char <= "Z":
                result.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(char)
        return "".join(result)

    # JSON
    @staticmethod
    def json_encode(data: str) -> str:
        """JSON encode a string (escape special characters)."""
        return json.dumps(data)

    @staticmethod
    def json_decode(data: str) -> str:
        """JSON decode a string."""
        return json.loads(data)

    # All encodings at once
    @classmethod
    def encode_all(cls, data: str) -> dict[str, str]:
        """Return all encodings for a given string."""
        return {
            "original": data,
            "base64": cls.base64_encode(data),
            "url": cls.url_encode(data),
            "double_url": cls.double_url_encode(data),
            "hex": cls.hex_encode(data),
            "hex_sql": cls.hex_encode_sql(data),
            "html": cls.html_encode(data),
            "html_entity": cls.html_entity_encode(data),
            "unicode": cls.unicode_encode(data),
            "binary": cls.binary_encode(data),
            "rot13": cls.rot13(data),
        }

    # SQLi specific encodings
    @staticmethod
    def char_encode_mysql(data: str) -> str:
        """Encode to MySQL CHAR() format."""
        chars = ",".join(str(ord(c)) for c in data)
        return f"CHAR({chars})"

    @staticmethod
    def char_encode_mssql(data: str) -> str:
        """Encode to MSSQL CHAR() format."""
        return "+".join(f"CHAR({ord(c)})" for c in data)

    @staticmethod
    def concat_encode_oracle(data: str) -> str:
        """Encode using Oracle CHR() concatenation."""
        return "||".join(f"CHR({ord(c)})" for c in data)


def encode_payload(payload: str, encoding: str) -> str:
    """Encode a payload using specified encoding type."""
    encoders = {
        "base64": Encoder.base64_encode,
        "url": Encoder.url_encode,
        "double_url": Encoder.double_url_encode,
        "hex": Encoder.hex_encode,
        "html": Encoder.html_encode,
        "unicode": Encoder.unicode_encode,
        "rot13": Encoder.rot13,
    }

    if encoding not in encoders:
        raise ValueError(f"Unknown encoding: {encoding}")

    return encoders[encoding](payload)
