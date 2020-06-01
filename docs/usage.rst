=====
Usage
=====

To use encryption2fa in a project::

    import encryption2fa


===============
Getting started
===============

Use this package to securely save and read back in sensitive data from an unsecure
source, e.g. from a cloud storage.
The data is protected by two factors:

1. A secret string saved in the ``.env``- file: ...
2. ...

Any data that works with ``pickle`` can be used. The main functionality is shown below:

.. code-block:: python

    from encryption import read_encrypted, save_encrypted, clear_password_cache
    data = "any data that can be pickled, a string in this case"
    file = "testoutput.encrypted"
    save_encrypted(data=data, file=file)
    data_plaintext = read_encrypted(file)
