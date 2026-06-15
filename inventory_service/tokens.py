"""Session token helpers — symmetric (Fernet) tokens only."""

from cryptography.fernet import Fernet


def issue_token(key, payload):
    """Issue a Fernet token."""
    return Fernet(key).encrypt(payload)


def read_token(key, token):
    return Fernet(key).decrypt(token)
