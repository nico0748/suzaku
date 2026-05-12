"""Zip Slip fixture for Suzaku Compass tests."""

import zipfile
import tarfile


def unsafe_unzip(path: str, dest: str) -> None:
    with zipfile.ZipFile(path) as z:
        z.extractall(dest)  # no path canonicalization


def unsafe_untar(path: str, dest: str) -> None:
    with tarfile.open(path) as t:
        for member in t.getmembers():
            t.extract(member, dest)
