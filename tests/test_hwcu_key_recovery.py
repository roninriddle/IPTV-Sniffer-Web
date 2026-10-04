"""Tests for the owner-local, offline HWCU numeric key recovery helper."""

import multiprocessing

from Crypto.Cipher import DES
from tools import recover_hwcu_key as recovery


def test_offline_numeric_recovery_saves_match_without_printing_key(tmp_path, monkeypatch):
    context = multiprocessing.get_context("spawn")
    for name in ("Event", "Queue", "Process"):
        monkeypatch.setattr(recovery.mp, name, getattr(context, name))
    key = b"00000042"
    plaintext = b"12345678$challenge$userid$stbid$ip$mac$$CTC".ljust(48, b"\x00")
    ciphertext = DES.new(key, DES.MODE_ECB).encrypt(plaintext)
    monkeypatch.setattr(recovery, "_authenticator_blocks", lambda _path: [ciphertext])

    secret = tmp_path / "epg-key.secret"
    status = tmp_path / "status.json"
    assert recovery.recover_numeric_key(
        tmp_path / "capture.pcap",
        secret,
        status,
        start=40,
        end=45,
        workers=1,
    ) is True
    assert recovery.LocalSecretStore(secret).get_epg_key() == key.decode("ascii")
    assert '"status": "found"' in status.read_text(encoding="utf-8")
