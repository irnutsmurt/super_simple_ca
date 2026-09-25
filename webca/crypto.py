"""Password-wrapped secret storage for the optional CA auto-unlock feature.

The CA passphrase is encrypted with a key derived (scrypt) from the web-UI login
password. Only the wrapped token and a random salt are stored at rest; they are
useless without the login password, which is never stored in cleartext (the
login check uses a separate one-way Werkzeug hash). If the login password is
weak, an attacker with the stored blob could brute-force it offline — so this
trades a little at-rest safety for convenience. Use a strong login password.
"""
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

# scrypt cost parameters (~tens of MB, ~100ms) — deliberately expensive.
_N, _R, _P = 2 ** 15, 8, 1
_MAXMEM = 128 * 1024 * 1024


def new_salt():
    return os.urandom(16)


def _derive(password, salt):
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                        n=_N, r=_R, p=_P, dklen=32, maxmem=_MAXMEM)
    return base64.urlsafe_b64encode(dk)


def wrap(password, salt, plaintext):
    """Encrypt `plaintext` under a key derived from `password`+`salt`."""
    return Fernet(_derive(password, salt)).encrypt(plaintext.encode("utf-8")).decode("ascii")


def unwrap(password, salt, token):
    """Return the plaintext, or None if the password/salt/token don't match."""
    try:
        return Fernet(_derive(password, salt)).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def salt_to_hex(salt):
    return salt.hex()


def salt_from_hex(hexstr):
    return bytes.fromhex(hexstr)


# --- machine-key wrapping (for the "persist across restart" option) -----------
# Here the wrapping key is a random file on the box (not a human password), so
# the process can decrypt unattended at boot. This means the secret is only as
# safe as the machine's filesystem — see the warning shown in the UI.
def new_machine_key():
    return Fernet.generate_key()  # 44-char urlsafe base64 bytes


def machine_wrap(key, plaintext):
    return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def machine_unwrap(key, token):
    try:
        return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
