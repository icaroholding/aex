from __future__ import annotations

import os
import stat

import pytest

from aex_sdk import Identity
from aex_sdk.errors import IdentityError
from aex_sdk.identity import verify_signature


def test_generate_produces_valid_agent_id(tmp_path) -> None:
    ident = Identity.generate(org="acme", name="alice")
    assert ident.agent_id.startswith("spize:acme/alice:")
    assert len(ident.fingerprint) == 6
    assert all(c in "0123456789abcdef" for c in ident.fingerprint)


def test_deterministic_from_secret() -> None:
    secret = b"\x07" * 32
    a = Identity.from_secret("acme", "alice", secret)
    b = Identity.from_secret("acme", "alice", secret)
    assert a.agent_id == b.agent_id
    assert a.public_key_bytes == b.public_key_bytes


def test_sign_and_verify_roundtrip() -> None:
    ident = Identity.generate(org="acme", name="alice")
    sig = ident.sign(b"hello")
    assert verify_signature(ident.public_key_bytes, b"hello", sig)
    assert not verify_signature(ident.public_key_bytes, b"hxllo", sig)


def test_save_load_roundtrip(tmp_path) -> None:
    ident = Identity.generate(org="acme", name="alice")
    path = tmp_path / "alice.key"
    ident.save(path)
    loaded = Identity.load(path)
    assert loaded.agent_id == ident.agent_id
    assert loaded.public_key_bytes == ident.public_key_bytes
    assert loaded.private_key_bytes == ident.private_key_bytes


def test_save_refuses_overwrite(tmp_path) -> None:
    ident = Identity.generate(org="acme", name="alice")
    path = tmp_path / "alice.key"
    ident.save(path)
    with pytest.raises(IdentityError):
        ident.save(path)
    # With overwrite=True it succeeds.
    ident.save(path, overwrite=True)


def test_saved_file_has_0600_perms(tmp_path) -> None:
    ident = Identity.generate(org="acme", name="alice")
    path = tmp_path / "alice.key"
    ident.save(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600 perms, got {oct(mode)}"


def test_tampered_file_rejected(tmp_path) -> None:
    ident = Identity.generate(org="acme", name="alice")
    path = tmp_path / "alice.key"
    ident.save(path)
    # Corrupt the stored public_key_hex so it mismatches the private key.
    content = path.read_text()
    content = content.replace(ident.public_key_hex, "00" * 32)
    path.write_text(content)
    with pytest.raises(IdentityError, match="public_key_hex"):
        Identity.load(path)


def test_bad_org_rejected() -> None:
    with pytest.raises(IdentityError):
        Identity.generate(org="acme corp", name="alice")


def test_empty_name_rejected() -> None:
    with pytest.raises(IdentityError):
        Identity.generate(org="acme", name="")


def test_bad_secret_length_rejected() -> None:
    with pytest.raises(IdentityError):
        Identity.from_secret("acme", "alice", b"short")
