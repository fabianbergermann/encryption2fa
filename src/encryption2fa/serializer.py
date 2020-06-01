import builtins
import io
import pickle

import pandas as pd
# TODO add json serializer, e.g. see: https://medium.com/@busybus/zipjson-3ed15f8ea85d


def serializer_pickle(data) -> bytes:
    return pickle.dumps(data)


def deserializer_pickle(data: bytes):
    return restricted_loads(data)


def serializer_parquet(df: pd.DataFrame) -> bytes:
    """
    Serializes a dataframe df using the parquet file format.
    # requires pyspark to read parquet file
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a DataFrame")
    buffer = io.BytesIO()
    df.to_parquet(buffer, engine="pyarrow", compression="snappy")
    return buffer.getvalue()


def deserializer_parquet(data: bytes):
    """
    Deserializes a dataframe df using the parquet file format.
    # requires pyspark to read parquet file
    """
    pathlike = io.BytesIO(data)
    return pd.read_parquet(pathlike, engine="pyarrow")


class RestrictedUnpickler(pickle.Unpickler):
    """ make un-pickling safer.
    see. https://docs.python.org/3/library/pickle.html
    """

    def find_class(self, module, name):
        safe_builtins = {
            "range",
            "complex",
            "set",
            "frozenset",
            "slice",
        }
        # Only allow safe classes from builtins.
        if module == "builtins" and name in safe_builtins:
            return getattr(builtins, name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))


def restricted_loads(s):
    """Safety-enhanced replacement function for pickle.loads().

    :Example:
    >>> restricted_loads(pickle.dumps(io.BytesIO()))
    Traceback (most recent call last):
        ...
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
    _pickle.UnpicklingError: global '_io.BytesIO' is forbidden
    """
    return RestrictedUnpickler(io.BytesIO(s)).load()
