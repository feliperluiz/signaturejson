from __future__ import (print_function, division, unicode_literals, absolute_import)

from kkmip import enums


def test_or():
    mask = enums.CryptographicUsageMask.Encrypt | enums.CryptographicUsageMask.Decrypt
    assert mask == enums.CryptographicUsageMask.Encrypt.value | enums.CryptographicUsageMask.Decrypt.value

    mask = (enums.CryptographicUsageMask.Encrypt
            | enums.CryptographicUsageMask.Decrypt
            | enums.CryptographicUsageMask.Sign)
    assert mask == (enums.CryptographicUsageMask.Encrypt.value
                    | enums.CryptographicUsageMask.Decrypt.value
                    | enums.CryptographicUsageMask.Sign.value)
