"""Intentionally vulnerable Python fixture for Suzaku Compass tests.

DO NOT use this code. It exists only as scanner bait.
"""

import pickle
import subprocess
import os
import marshal
import xml.etree.ElementTree as ET  # noqa: N817
import yaml


def unsafe_pickle(data: bytes):
    return pickle.loads(data)


def unsafe_yaml(text: str):
    return yaml.load(text)  # missing SafeLoader


def safe_yaml(text: str):
    return yaml.load(text, Loader=yaml.SafeLoader)


def unsafe_subprocess(user_input: str):
    subprocess.run(user_input, shell=True)


def unsafe_os_system(cmd: str):
    os.system(cmd)


def unsafe_eval(expr: str):
    return eval(expr)


def unsafe_exec(code: str):
    exec(code)


def unsafe_marshal(data: bytes):
    return marshal.loads(data)


def unsafe_xml(payload: str):
    return ET.fromstring(payload)
