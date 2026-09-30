"""Encryption at rest for secrets Hydra must be able to read back (a
webhook's HMAC signing secret, a ticketing integration's API token) —
unlike account API keys, which are only ever hashed.

Fernet (authenticated: AES-128-CBC with an HMAC-SHA256 tag) keyed by
`HYDRA_API_SECRETS_KEYS`, a comma-separated list: the first key encrypts,
every key can decrypt, so a key is rotated by putting the new one first and
dropping the old one once `ControlDB.seal_plaintext_secrets` / re-saves
have moved everything over. Generate a key with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

Sealed values carry a version prefix, so a stored value is unambiguously
either sealed or legacy plaintext (webhook secrets written before this
existed); `reveal` returns legacy plaintext unchanged. Never log a
revealed value.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

SEALED_PREFIX = "enc:v1:"


class SecretsUnavailableError(RuntimeError):
    """A sealed value can't be read (no key configured, or none of the
    configured keys matches) — fail closed rather than guess."""


class SecretBox:
    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise ValueError("at least one key is required")
        try:
            self._fernet = MultiFernet([Fernet(key.strip().encode()) for key in keys])
        except ValueError as exc:
            raise ValueError("HYDRA_API_SECRETS_KEYS must be comma-separated Fernet keys") from exc

    def seal(self, plaintext: str) -> str:
        return SEALED_PREFIX + self._fernet.encrypt(plaintext.encode()).decode()

    def reveal(self, stored: str) -> str:
        """Plaintext of a stored value (legacy plaintext returned as-is)."""
        if not is_sealed(stored):
            return stored
        try:
            return self._fernet.decrypt(stored[len(SEALED_PREFIX) :].encode()).decode()
        except InvalidToken as exc:
            raise SecretsUnavailableError("no configured key can decrypt this secret") from exc


def is_sealed(stored: str) -> bool:
    return stored.startswith(SEALED_PREFIX)


def reveal(stored: str, box: SecretBox | None) -> str:
    """The plaintext of a stored value: legacy plaintext as-is, a sealed
    value decrypted with `box`."""
    if not is_sealed(stored):
        return stored
    if box is None:
        raise SecretsUnavailableError("a sealed secret needs HYDRA_API_SECRETS_KEYS")
    return box.reveal(stored)


def box_from_keys(raw: str | None) -> SecretBox | None:
    keys = [key for key in (raw or "").split(",") if key.strip()]
    return SecretBox(keys) if keys else None
