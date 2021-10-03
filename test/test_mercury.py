import pytest

import src.mercury.mercury as mercury


def test_repr_byte_arr():
    barr = b"\x01\x02\x03"
    assert mercury.repr_byte_arr(barr) == "01 02 03"


def test_crc16():
    assert mercury.crc16(b"\x00\x02") == bytearray(b"\x80\x71")
    assert mercury.crc16(b"\x00\x00") == bytearray(b"\x01\xb0")
    assert mercury.crc16(b"\x00\x01\x02\x02\x02\x02\x02\x02\x02") == bytearray(
        b"\xb0\x07"
    )
