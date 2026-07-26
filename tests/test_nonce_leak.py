"""Regression test for nonce leak in nv-attestation-cli/src/attest.cpp."""

import pathlib
import re


def test_attest_nonce_is_raii_managed():
    """The user-supplied nonce in attest() must be owned by nv_unique_ptr so it is freed."""
    attest_path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "nv-attestation-cli"
        / "src"
        / "attest.cpp"
    )
    source = attest_path.read_text()

    # The fix declares the nonce handle with the RAII wrapper used by collect_evidence.cpp.
    assert re.search(r"nv_unique_ptr<nvat_nonce_t>\s+nonce;", source), (
        "attest.cpp should manage nonce with nv_unique_ptr<nvat_nonce_t>"
    )

    # The raw handle is populated by nvat_nonce_from_hex and then moved into the wrapper.
    assert "nonce.reset(&raw_nonce);" in source, (
        "attest.cpp should transfer the raw nonce into the RAII wrapper"
    )

    # The wrapped handle is passed to nvat_attest_device.
    assert "*(nonce.get())" in source, (
        "attest.cpp should pass the wrapped nonce to nvat_attest_device"
    )

    # Pre-fix code used a raw handle and never freed it; ensure that pattern is gone.
    assert "nvat_nonce_t nonce = nullptr;" not in source, (
        "attest.cpp should not use a raw nvat_nonce_t nonce handle"
    )
