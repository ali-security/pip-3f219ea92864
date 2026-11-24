"""Tests for the CA bundle shipped with the vendored certifi package.

These guard against pip trusting root certificates that have been
distrusted/removed from the Mozilla trust store (CVE-2026-133949).
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import ssl

import pytest

from pip._vendor import certifi

# SHA-256 fingerprints (of the DER encoding) of roots that were removed from
# the bundle and must no longer be trusted.
REMOVED_ROOTS = {
    "Atos TrustedRoot 2011": (
        "f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474"
    ),
    "emSign ECC Root CA - G3": (
        "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
    ),
}

# SHA-256 fingerprints of roots that were added to the bundle.
ADDED_ROOTS = {
    "SECOM TLS RSA Root CA 2024": (
        "1435f225c5d252d7a21948cc3ce62aecfa88001e3dd72d1cc3555100eb372f93"
    ),
    "SECOM TLS ECC Root CA 2024": (
        "6ab2ab75f51cb4f4f0156203fbf6f646232f514be059f62833308b82b4d72db1"
    ),
    "Telia EC TLS Root CA v3": (
        "098e08a91dbbf77478b96cceb89b1413a5da37b7c862606a955deb07179f4326"
    ),
    "Telia RSA TLS Root CA v3": (
        "d13db1294c45ebc6fc86c6bbf69fa29bdfe692dff7c713c243c7a956c6a2284c"
    ),
}

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)


def _ssl_context_fingerprints() -> set[str]:
    context = ssl.create_default_context(cafile=certifi.where())
    return {
        hashlib.sha256(der).hexdigest()
        for der in context.get_ca_certs(binary_form=True)
    }


def _bundle_text_fingerprints() -> set[str]:
    fingerprints: set[str] = set()
    for match in _PEM_RE.finditer(certifi.contents()):
        der = base64.b64decode("".join(match.group(1).split()))
        fingerprints.add(hashlib.sha256(der).hexdigest())
    return fingerprints


def test_ca_bundle_exists() -> None:
    assert os.path.isfile(certifi.where())


def test_ca_bundle_loads_into_ssl_context() -> None:
    assert len(_ssl_context_fingerprints()) > 100


@pytest.mark.parametrize("label", sorted(REMOVED_ROOTS))
def test_removed_root_not_trusted(label: str) -> None:
    fingerprint = REMOVED_ROOTS[label]
    assert fingerprint not in _ssl_context_fingerprints()
    assert fingerprint not in _bundle_text_fingerprints()


@pytest.mark.parametrize("label", sorted(ADDED_ROOTS))
def test_added_root_trusted(label: str) -> None:
    fingerprint = ADDED_ROOTS[label]
    assert fingerprint in _ssl_context_fingerprints()
    assert fingerprint in _bundle_text_fingerprints()
