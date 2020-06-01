import unittest
from io import StringIO
from unittest import mock, TestCase


def get_test_dataframe():
    import pandas as pd
    import numpy as np
    df = pd.DataFrame(
        {
            "one": [-1, np.nan, 2.5],
            "two": ["foo", "bar", "baz"],
            "three": [True, False, True],
            "four": ["foo", "bar", "baz"],
        },
        index=list("abc"),
    )
    df.four = df.four.astype("category")
    return df


class Test(TestCase):
    @mock.patch("sys.stdin")
    def test_uses_stdin_as_default_input(self, mock_input):
        import getpass

        mock_input.readline.return_value = "input_string"
        getpass._raw_input(stream=StringIO())
        mock_input.readline.assert_called_once_with()

    @mock.patch("getpass.getpass")
    @mock.patch.dict(
        "os.environ",
        {"SALT_FOR_PASSWORD_HASH": "V4MN73IxjLtAB2HmU3E50e4tZjjddOZRjsBl1ogqkPA="},
    )
    def test_get_hashed_input_password(self, mock_getpass):
        from encryption2fa.encryption import get_user_key

        mock_getpass.return_value = "dfdfdfdf"
        out = get_user_key()
        self.assertEqual(out, b"Upm3bmsC6yr1TY0P8G-m-mws6rnOqQVSgpukVGwP-gs=")

    @mock.patch("getpass.getpass")
    @mock.patch.dict("os.environ", {"SALT_FOR_PASSWORD_HASH": "some salt"})
    def test_decrypt_data_pickle(self, mock_getpass):
        from encryption2fa.encryption import encrypt_data, decrypt_data
        from encryption2fa.serializer import serializer_pickle, deserializer_pickle

        mock_getpass.return_value = "dfdfdfdf"
        salt = "some salt"
        data = "secret data as a string"
        token = encrypt_data(data=data, serializer=serializer_pickle, salt=salt)
        out = decrypt_data(token=token, deserializer=deserializer_pickle, salt=salt)
        self.assertEqual(data, out)

    @mock.patch("getpass.getpass")
    @mock.patch.dict("os.environ", {"SALT_FOR_PASSWORD_HASH": "some salt"})
    def test_decrypt_data_dataframe(self, mock_getpass):
        from encryption2fa.encryption import encrypt_data, decrypt_data
        from encryption2fa.serializer import serializer_parquet, deserializer_parquet

        df = get_test_dataframe()
        mock_getpass.return_value = "dfdfdfdf"
        salt = "some salt"
        token = encrypt_data(data=df, serializer=serializer_parquet, salt=salt)
        df_out = decrypt_data(token=token, deserializer=deserializer_parquet, salt=salt)
        self.assertTrue(df.equals(df_out))

    @mock.patch("getpass.getpass")
    @mock.patch.dict("os.environ", {"SALT_FOR_PASSWORD_HASH": "short salt"})
    def test_decrypt_data_fail(self, mock_getpass):
        from encryption2fa.encryption import decrypt_data
        from encryption2fa.serializer import serializer_pickle
        from cryptography.fernet import InvalidToken

        mock_getpass.return_value = "dfdfdfdf"
        salt = "some salt"
        self.assertRaises(
            InvalidToken, decrypt_data, b"invalid token", serializer_pickle, salt
        )

    @mock.patch("getpass.getpass")
    @mock.patch.dict("os.environ", {"SALT_FOR_PASSWORD_HASH": "short salt"})
    def test_read_encrypted(self, mock_getpass):
        from encryption2fa.encryption import save_encrypted, read_encrypted

        mock_getpass.return_value = "dfdfdfdf"
        testfile = "testfile.encrypted"
        data = get_test_dataframe()
        save_encrypted(data=data, file=testfile)
        data_out = read_encrypted(file=testfile)
        self.assertTrue(data.equals(data_out))


if __name__ == "__main__":
    unittest.main()
