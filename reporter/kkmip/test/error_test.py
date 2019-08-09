from __future__ import (print_function, division, unicode_literals, absolute_import)

from kkmip import enums
from kkmip import error


def init_test():
    e = error.KmipError(
        enums.ResultStatus.OperationFailed,
        enums.ResultReason.CryptographicFailure,
        'Failure'
    )
    assert e.result_status == enums.ResultStatus.OperationFailed
    assert e.result_reason == enums.ResultReason.CryptographicFailure
    assert e.result_message == 'Failure'
    assert str(e)
