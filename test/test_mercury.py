import pytest

import src.mercury.mercury as mercury

def test_repr_byte_arr():
    barr = b'\x01\x02\x03'
    assert mercury.repr_byte_arr(barr) == '01 02 03'