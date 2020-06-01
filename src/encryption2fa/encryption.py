"""
encryption.py
====================================
This is the module-level docstring

# source: http://www.cs.utexas.edu/~bwaters/publications/papers/www2005.pdf
# source: https://medium.com/asecuritysite-when-bob-met-alice/
# passing-encrypted-tokens-the-fernet-way-ef9b2a9d125d
# source: https://medium.com/coinmonks/
# if-youre-struggling-picking-a-crypto-suite-fernet-may-be-the-answer-95196c0fec4b
# source: https://nitratine.net/blog/post/encryption-and-decryption-in-python/
# Fernet specs: https://github.com/fernet/spec/blob/master/Spec.md
"""
# TODO Add (optional) logic to the encryption:
#  check if the encrypted file can be decrypted, yielding the exact same result

import base64
import functools
import getpass
import os
import time

import dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from encryption2fa.serializer import deserializer_parquet, serializer_parquet


def get_salt_from_env() -> bytes:
    """ Retrieve the salt from an environment variable with key "SALT_FOR_PASSWORD_HASH"
    .. Warning::
    Keep the salt secret for improved input password protection!

    >>> get_salt_from_env()
    b'V4MN73IxjLtAB2HmU3E50e4tZjjddOZRjsBl1ogqkPA='
    """
    dotenv.load_dotenv()
    salt = os.getenv("SALT_FOR_PASSWORD_HASH")
    if salt is None:
        print(
            "*** WARNING: No Salt found for the password hashing! *** \n"
            "This might thrown an error in the future. \n"
            "Using a default salt instead..."
        )
        salt = "St6jlEKLJ2gVJrcDdNDsTPJZ5bmMI4t-vyjscRpsstE="
    return salt.encode()


def hash_password_with_salt(key: bytes, salt: bytes) -> bytes:
    """ Hash a key (or password) using a secure hashing function with a salt.

    To increase security against brute force attacs, increase the parameter n (must be
    a power of two). The choice of n=2**18 should yield approx. 0.7s runtime on a
    modern notebook, as a tradeoff of security and convencience.

    >>> hash_password_with_salt(key=b"my password", salt=b"my salt")
    b'lzxAZtZ7znXCVgDokfGZdjudgrXO9TabIU9-6eyvsw4='
    """
    kdf = Scrypt(salt=salt, length=32, n=2 ** 18, r=8, p=1, backend=default_backend(), )
    return base64.urlsafe_b64encode(kdf.derive(key))


def validate_password(password: str):
    """ Validate the user password

    >>> validate_password("short")
    Traceback (most recent call last):
    ...
        raise ValueError("password must have at least 8 characters")
    ValueError: password must have at least 8 characters
    >>> validate_password("This is a good password!")
    'This is a good password!'
    """
    minlen = 8
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(password) < minlen:
        raise ValueError("password must have at least 8 characters")
    return password


@functools.lru_cache(maxsize=4)
def hash_and_memoize_user_password(salt: bytes) -> bytes:
    """ Protect a user password with a secure hash. Memoize result for convenience.
    Providing the salt as input to the memoized function avoids side effects of the
    function when the salt is changed, for example during testing.
    ..Note::
    This implementation leaks the salt into the computer RAM. Knowledge of the salt
    makes a brute-force attack on the input password easier. Still this is an
    acceptable behaviour, as the RAM is considered a safe environment in this scope.
    """

    password = getpass.getpass()
    key = validate_password(password).encode()
    return hash_password_with_salt(key=key, salt=salt)


def get_user_key() -> bytes:
    """ Protect a user password with a secure hash."""
    salt = get_salt_from_env()
    return hash_and_memoize_user_password(salt)


def get_fernet_key(key: bytes) -> bytes:
    """ Derive a valid fernet key from an arbitrary-length key (or password).

    >>> get_fernet_key(b"my passwd")
    b'IoNIrq0z4XYkDv_lt5qAc-elNAfbkvErUkzsMLt39qM='
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key)
    return base64.urlsafe_b64encode(digest.finalize())


def get_fernet_object(key: bytes = None, fernet_salt: bytes = b"") -> Fernet:
    """ Provides a fernet object

    >>> get_fernet_object(b"bla", b"blo") #doctest: +ELLIPSIS
    Caution: This is is an unsafe mode. Please use this for debugging only!
    <cryptography.fernet.Fernet object at 0x...>
    """
    if key:
        print("Caution: This is is an unsafe mode. Please use this for debugging only!")
    else:
        key = get_user_key()
    return Fernet(get_fernet_key(key + fernet_salt))


def print_encryption_timestamp(fernet_object: Fernet, token: bytes) -> None:
    """ Print the encryption timestamp of a token in raw and human-readable form"""
    timestamp = fernet_object.extract_timestamp(token)
    print(
        f"Timestamp of encryption: {timestamp} \n"
        f"Date created: {time.ctime(timestamp)}"
    )


def encrypt_with_fernet(data: bytes, fernet: Fernet) -> bytes:
    """
    >>> fernet = get_fernet_object(b"pwd", b"salt..")
    Caution: This is is an unsafe mode. Please use this for debugging only!
    >>> encrypt_with_fernet(data=b"my data", fernet=fernet) #doctest: +ELLIPSIS
    Timestamp of encryption: ...
    Date created: ...
    b'...
    """
    token = fernet.encrypt(data)
    print_encryption_timestamp(fernet, token)
    return token


def decrypt_with_fernet(token: bytes, fernet: Fernet) -> bytes:
    """
    >>> fernet = get_fernet_object(b"pwd", b"salt..")
    Caution: This is is an unsafe mode. Please use this for debugging only!
    >>> token = encrypt_with_fernet(data=b"my data", fernet=fernet) #doctest: +ELLIPSIS
    Timestamp of encryption: ...
    Date created: ...
    >>> decrypt_with_fernet(token, fernet) #doctest: +ELLIPSIS
    Timestamp of encryption: ...
    Date created: ...
    b'my data'
    """
    print_encryption_timestamp(fernet, token)
    return fernet.decrypt(token)


def get_new_salt(salt_length: int = 32):
    """
    >>> salt = get_new_salt(salt_length=32) #doctest: +ELLIPSIS
    New salt created: 'b...
    """
    salt = base64.urlsafe_b64encode(os.urandom(salt_length))
    print(f"New salt created: '{salt!r}'")
    return salt


def encrypt_data(data, serializer, salt: str = "") -> bytes:
    fernet = get_fernet_object(fernet_salt=salt.encode())
    return encrypt_with_fernet(data=serializer(data), fernet=fernet)


def decrypt_data(token: bytes, deserializer, salt: str = ""):
    fernet = get_fernet_object(fernet_salt=salt.encode())
    return deserializer(decrypt_with_fernet(token=token, fernet=fernet))


def save_encrypted(data, file: str) -> None:
    filename = os.path.basename(file)
    encrypted_data = encrypt_data(
        data=data, serializer=serializer_parquet, salt=filename
    )
    with open(file, "wb") as f:
        f.write(encrypted_data)


def read_encrypted(file: str):
    filename = os.path.basename(file)
    with open(file, "rb") as f:
        token = f.read()
    return decrypt_data(token=token, deserializer=deserializer_parquet, salt=filename)


def clear_password_cache():
    """
    >>> clear_password_cache()
    """
    hash_and_memoize_user_password.cache_clear()


if __name__ == "__main__":
    import doctest
    import unittest

    print(doctest.testmod())

    suite = unittest.TestLoader().loadTestsFromName("test_encryption")
    unittest.TextTestRunner(verbosity=2).run(suite)
