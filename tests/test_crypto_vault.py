"""Tests for crypto_vault module (DPAPI + authenticated encryption)."""
from pathlib import Path
import pytest
from gitghost import crypto_vault
from gitghost.crypto_vault import SecretVault, _portable_encrypt, _portable_decrypt, _encrypt_blob, _decrypt_blob

def test_portable_crypto_roundtrip():
    data = b"super-secret-token-12345"
    enc = _portable_encrypt(data)
    assert enc != data
    assert enc.startswith(b"PORT:")
    dec = _portable_decrypt(enc)
    assert dec == data

def test_portable_crypto_tampering():
    data = b"secret-token"
    enc = _portable_encrypt(data)
    # Corrupt a byte in ciphertext
    tampered = enc[:-5] + bytes([(enc[-5] ^ 0xFF)]) + enc[-4:]
    with pytest.raises(Exception):
        _portable_decrypt(tampered)

def test_blob_encrypt_decrypt_roundtrip():
    plain = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    encrypted = _encrypt_blob(plain)
    assert encrypted != plain
    decrypted = _decrypt_blob(encrypted)
    assert decrypted == plain

def test_vault_set_get_remove(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_vault_file = tmp_path / "test_vault.enc"
    monkeypatch.setattr(crypto_vault, "_get_vault_file_path", lambda: test_vault_file)
    SecretVault._CACHE = None
    
    assert SecretVault.get("github_token") is None
    
    SecretVault.set("github_token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    assert SecretVault.get("github_token") == "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    
    # Reset cache to simulate process restart and reading from encrypted file
    SecretVault._CACHE = None
    assert SecretVault.get("github_token") == "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    
    # Masked view
    masked = SecretVault.list_keys_masked()
    assert "github_token" in masked
    assert masked["github_token"].startswith("ghp_")
    assert "1234567890" not in masked["github_token"]
    
    # Delete
    assert SecretVault.remove("github_token") is True
    assert SecretVault.get("github_token") is None
    assert SecretVault.remove("non_existent") is False
    
    SecretVault._CACHE = None
