#!/usr/bin/env python3
"""Issue an explicitly authorized DE API Render deploy without storing hook credentials in Git.

Set RENDER_DEPLOY_HOOK_URL in an operator-controlled environment or a CI secret.
Do not print, persist, or put the URL into command-line arguments.
An exposed previous deployment hook MUST be rotated/revoked at Render:
removing it from HEAD does not remove it from Git history.
"""
import os
import re
import sys
import urllib.request
import urllib.error
from urllib.parse import urlsplit


def validated_hook():
    value = os.environ.get("RENDER_DEPLOY_HOOK_URL", "").strip()
    if not value:
        raise ValueError("RENDER_DEPLOY_HOOK_URL not configured")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or parts.hostname != "api.render.com"
        or parts.username
        or parts.password
        or parts.port is not None
        or not re.fullmatch(r"/deploy/srv-[A-Za-z0-9]+", parts.path)
        or not re.fullmatch(r"key=[A-Za-z0-9_-]+", parts.query)
        or parts.fragment
    ):
        raise ValueError("RENDER_DEPLOY_HOOK_URL has unexpected shape")
    return value


def main():
    try:
        url = validated_hook()
        # No logging or exception text that could expose the hook URL.
        request = urllib.request.Request(url, data=b"", method="POST")
        with urllib.request.urlopen(request, timeout=20) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError("Deploy trigger did not return HTTP 2xx")
        print("DE API Render deploy requested using operator-provided hook.")
        return 0
    except (ValueError, urllib.error.URLError, TimeoutError, OSError, RuntimeError):
        print("DE API deploy NOT requested: missing/invalid hook or upstream refusal.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
