import pytest
from unittest.mock import MagicMock, patch, PropertyMock

import src.mercury.mercury as mercury
from src.mercury.mercury import MercuryRequest


def test_repr_byte_arr():
    barr = b"\x01\x02\x03"
    assert mercury.repr_byte_arr(barr) == "01 02 03"


def test_crc16():
    assert mercury.crc16(b"\x00\x02") == bytearray(b"\x80\x71")
    assert mercury.crc16(b"\x00\x00") == bytearray(b"\x01\xb0")
    assert mercury.crc16(b"\x00\x01\x02\x02\x02\x02\x02\x02\x02") == bytearray(
        b"\xb0\x07"
    )


class TestMercuryRequest:
    def test___init__(self):
        req = mercury.MercuryRequest(address=0, request_code=0)
        assert req.request_code == 0
        assert req.address == 0
        assert req.params == None
        assert req._value == None

    @patch('src.mercury.mercury.MercuryRequest.value', new_callable=PropertyMock)
    def test___len__(self, mock_value):
        mock_value.return_value = 'foobar'
        req = MercuryRequest(address=0, request_code=0)
        assert len(req) == 6

    @patch('src.mercury.mercury.repr_byte_arr')
    @patch('src.mercury.mercury.MercuryRequest.value', new_callable=PropertyMock)
    def test___repr__(self, mock_value, mock_repr_byte_arr):
        mock_value.return_value = 'foobar'
        mock_repr_byte_arr.return_value = 'FO OB AR'
        req = MercuryRequest(address=0, request_code=0)
        assert repr(req) == 'FO OB AR'
        mock_repr_byte_arr.assert_called_with('foobar')

    @patch('struct.pack')
    @patch('src.mercury.mercury.crc16')
    def test_value(self, mock_crc16, mock_struct_pack):
        req = MercuryRequest(address=0, request_code=0)
        req._value = 'foobar'
        assert req.value == 'foobar'

        req = MercuryRequest(address=0, request_code=0)
        mock_struct_pack.return_value = 'foobar'
        mock_crc16.return_value = 'baz'
        assert req.value == 'foobarbaz'

        req = MercuryRequest(address=0, request_code=0, args='boo')
        assert req.value == 'foobarboobaz'

