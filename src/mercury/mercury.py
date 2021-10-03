"""
Implements Mercury Protocol for version 05.2021

"""

import struct
import time
import logging
import random

import serial


WAIT_RESPONSE = 0.150


class MercuryConnectionException(Exception):
    pass


class MercuryReplyDataError(ValueError):
    pass


class MercuryADDR:
    """
    Address constants
    """

    UNIVERSAL = 0x00
    UNICAST_SPACE = range(0x01, 0xF1)
    BROADCAST = 0xFE
    RESERVED = range(0xF1, 0xFF + 1)


class MercuryOPS:
    """
    Supported Operation codes
    """

    TEST = 0
    OPEN = 1
    CLOSE = 2


class MercuryLEVEL:
    """
    User levels for MercuryOPS.OPEN
    """

    USER = b"\x01"
    ADMIN = b"\x02"


class MercuryREPLY:
    """
    Reply Status Codes
    """

    OK = 0
    BAD_COMMAND = 1
    INTERNAL_ERROR = 2
    UNAUTHORIZED = 3
    CLOCK_SYNC = 4
    LOGIN_REQUIRED = 5


MercuryREPLYStatuses = {
    MercuryREPLY.OK: "Success",
    MercuryREPLY.BAD_COMMAND: "Bad command or operands",
    MercuryREPLY.INTERNAL_ERROR: "Counter Internal error",
    MercuryREPLY.UNAUTHORIZED: "Current level insufficient fro the operation",
    MercuryREPLY.CLOCK_SYNC: "Internal clock already sunchrnized",
    MercuryREPLY.LOGIN_REQUIRED: "Operation requires open channel",
}

SerialSPEEDS = (300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)

SerialEchoMODES = ("auto", "enabled", "disabled")


MercuryPASSWORD = {
    MercuryLEVEL.USER: 111111,
    MercuryLEVEL.ADMIN: 222222,
}


def repr_byte_arr(bytearr):
    return " ".join([f"{x:02X}" for x in bytearr])


def crc16(data: bytes):
    """
    CRC16-MODBUS adapted from Mercury Documentation
    """
    sr_crc_hi = bytearray(
        [
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x01,
            0xC0,
            0x80,
            0x41,
            0x00,
            0xC1,
            0x81,
            0x40,
        ]
    )
    sr_crc_low = bytearray(
        [
            0x00,
            0xC0,
            0xC1,
            0x01,
            0xC3,
            0x03,
            0x02,
            0xC2,
            0xC6,
            0x06,
            0x07,
            0xC7,
            0x05,
            0xC5,
            0xC4,
            0x04,
            0xCC,
            0x0C,
            0x0D,
            0xCD,
            0x0F,
            0xCF,
            0xCE,
            0x0E,
            0x0A,
            0xCA,
            0xCB,
            0x0B,
            0xC9,
            0x09,
            0x08,
            0xC8,
            0xD8,
            0x18,
            0x19,
            0xD9,
            0x1B,
            0xDB,
            0xDA,
            0x1A,
            0x1E,
            0xDE,
            0xDF,
            0x1F,
            0xDD,
            0x1D,
            0x1C,
            0xDC,
            0x14,
            0xD4,
            0xD5,
            0x15,
            0xD7,
            0x17,
            0x16,
            0xD6,
            0xD2,
            0x12,
            0x13,
            0xD3,
            0x11,
            0xD1,
            0xD0,
            0x10,
            0xF0,
            0x30,
            0x31,
            0xF1,
            0x33,
            0xF3,
            0xF2,
            0x32,
            0x36,
            0xF6,
            0xF7,
            0x37,
            0xF5,
            0x35,
            0x34,
            0xF4,
            0x3C,
            0xFC,
            0xFD,
            0x3D,
            0xFF,
            0x3F,
            0x3E,
            0xFE,
            0xFA,
            0x3A,
            0x3B,
            0xFB,
            0x39,
            0xF9,
            0xF8,
            0x38,
            0x28,
            0xE8,
            0xE9,
            0x29,
            0xEB,
            0x2B,
            0x2A,
            0xEA,
            0xEE,
            0x2E,
            0x2F,
            0xEF,
            0x2D,
            0xED,
            0xEC,
            0x2C,
            0xE4,
            0x24,
            0x25,
            0xE5,
            0x27,
            0xE7,
            0xE6,
            0x26,
            0x22,
            0xE2,
            0xE3,
            0x23,
            0xE1,
            0x21,
            0x20,
            0xE0,
            0xA0,
            0x60,
            0x61,
            0xA1,
            0x63,
            0xA3,
            0xA2,
            0x62,
            0x66,
            0xA6,
            0xA7,
            0x67,
            0xA5,
            0x65,
            0x64,
            0xA4,
            0x6C,
            0xAC,
            0xAD,
            0x6D,
            0xAF,
            0x6F,
            0x6E,
            0xAE,
            0xAA,
            0x6A,
            0x6B,
            0xAB,
            0x69,
            0xA9,
            0xA8,
            0x68,
            0x78,
            0xB8,
            0xB9,
            0x79,
            0xBB,
            0x7B,
            0x7A,
            0xBA,
            0xBE,
            0x7E,
            0x7F,
            0xBF,
            0x7D,
            0xBD,
            0xBC,
            0x7C,
            0xB4,
            0x74,
            0x75,
            0xB5,
            0x77,
            0xB7,
            0xB6,
            0x76,
            0x72,
            0xB2,
            0xB3,
            0x73,
            0xB1,
            0x71,
            0x70,
            0xB0,
            0x50,
            0x90,
            0x91,
            0x51,
            0x93,
            0x53,
            0x52,
            0x92,
            0x96,
            0x56,
            0x57,
            0x97,
            0x55,
            0x95,
            0x94,
            0x54,
            0x9C,
            0x5C,
            0x5D,
            0x9D,
            0x5F,
            0x9F,
            0x9E,
            0x5E,
            0x5A,
            0x9A,
            0x9B,
            0x5B,
            0x99,
            0x59,
            0x58,
            0x98,
            0x88,
            0x48,
            0x49,
            0x89,
            0x4B,
            0x8B,
            0x8A,
            0x4A,
            0x4E,
            0x8E,
            0x8F,
            0x4F,
            0x8D,
            0x4D,
            0x4C,
            0x8C,
            0x44,
            0x84,
            0x85,
            0x45,
            0x87,
            0x47,
            0x46,
            0x86,
            0x82,
            0x42,
            0x43,
            0x83,
            0x41,
            0x81,
            0x80,
            0x40,
        ]
    )
    initial_crc = 0xFFFF

    def update_crc(data_byte, old_crc):
        crc_array = bytearray(list(old_crc.to_bytes(2, byteorder="big")))
        i = crc_array[1] ^ data_byte
        crc_array[1] = crc_array[0] ^ sr_crc_hi[i]
        crc_array[0] = sr_crc_low[i]
        return int.from_bytes(crc_array, byteorder="big", signed=False)

    crc = initial_crc
    for data_byte in data:
        crc = update_crc(data_byte, crc)
    first = crc // 256
    second = crc % 256
    return bytearray([second, first])


class MercuryRequest:
    """
    Encodes Request messages
    """

    def __init__(self, address, request_code, args=None):
        self.address = address
        self.request_code = request_code
        self.params = args
        self._value = None
        self.format = "<BB"

    def __len__(self):
        return len(self.value)

    def __repr__(self):
        return repr_byte_arr(self.value)

    @property
    def value(self):
        """
        Encodes fields into a binary value
        """
        if self._value is None:
            self._value = struct.pack(
                self.format,
                self.address,
                self.request_code,
            )
            if self.params is not None:
                self._value += self.params
            self._value += crc16(self._value)
        return self._value


class MercuryReply:
    """
    Decodes Reply Messages from binary frames
    """

    def __init__(self, data, req_rep=False, verify=True):
        if len(data) < 1:
            m = "Empty data packet. Cannot parse."
            logging.critical(m)
            raise MercuryReplyDataError(m)

        self.trailer_offset = -2
        self.header_offset = 1
        if req_rep:
            self.header_offset += 1
        self._data = data
        self.format = "".join(["<B", "B" * (len(data) - self.header_offset - 2), "H"])
        self.parse_data(verify)

    def parse_data(self, verify=True):
        logging.debug(f"parsing reply: {repr_byte_arr(self._data)} using {self.format}")
        try:
            self.fields = list(struct.unpack(self.format, self._data))
        except Exception as e:
            m = f"failed to parse data {repr_byte_arr(self._data)} using {self.format}: {e}"
            logging.critical(m)
            raise
        logging.debug(f"parsed {repr_byte_arr(self._data)} into {self.fields} ({self.parsed_data})")
        logging.debug(f'addr: {self.addr}, status: {self.status}, checksum: {self.checksum}')

        if verify and not self.verify_checksum():
            crc = self.raw_checksum
            crc_d = self.checksum
            logging.warning(
                "bad checksum in %s: %s, expected %s",
                repr_byte_arr(self._data),
                repr_byte_arr(crc_d),
                repr_byte_arr(crc),
            )
        if not self.is_ok():
            logging.error(
                MercuryREPLYStatuses.get(self.status, f"Unknown error: {self.status}")
            )

    def __len__(self):
        return len(self._data)

    def __repr__(self):
        return repr_byte_arr(self._data)

    def verify_checksum(self):
        """
        Verifies Frame Checksum is correct
        """
        crc = self.raw_checksum
        crc_d = self.checksum
        return repr_byte_arr(crc_d) == repr_byte_arr(crc)

    @property
    def checksum(self):
        """
        Extracts frame checksum
        """
        return bytearray(self._data[self.trailer_offset:])

    @property
    def raw_checksum(self):
        """
        Extracts frame checksum
        """
        return crc16(self._data[: self.trailer_offset])

    @property
    def addr(self):
        """
        Extracts frame address
        """
        return self.fields[0]

    @property
    def raw_data(self):
        """
        Produce original binary data
        """
        return self._data

    @property
    def parsed_data(self):
        """
        Returns data extracted from the frame
        """
        return self.fields[self.header_offset : -1]

    @property
    def status(self):
        """
        Read status field from data
        """
        return self.parsed_data[0] & 0x07

    def is_ok(self):
        """
        True if operation status is OK (Success)
        """
        return self.status == MercuryREPLY.OK


class MercuryDriver:
    """
    Implements basic communcitation operations
    """

    def __init__(self, com, addr, speed=9600, echo_mode="auto"):
        try:
            assert speed in SerialSPEEDS
            assert addr in MercuryADDR.UNICAST_SPACE or addr == MercuryADDR.UNIVERSAL
            assert echo_mode in SerialEchoMODES
        except AssertionError as e:
            logging.critical(
                f"Driver Parameters out of range: {com},{addr}, {speed}; {e}"
            )
            raise

        self.com = com
        self.speed = speed
        self.test_com_port()

        self.addr = addr

        self.echo_mode = echo_mode
        if echo_mode == "auto":
            self.echo_mode = self.detect_serial_echo_mode()

    def test_com_port(self):
        logging.debug(f"Testing {self.com} at {self.speed} bps")
        try:
            with serial.Serial(
                self.com,
                self.speed,
                serial.EIGHTBITS,
                serial.PARITY_NONE,
                serial.STOPBITS_ONE,
            ) as ser:
                return ser.isOpen()
        except serial.serialutil.SerialException as e:
            logging.critical(f"Failed to open {self.com} at {self.speed} bps")
            raise

    def communicate(self, req):
        """
        Opens serial port, sends request, reads reply.
        Detects and strips CAN echo when possible.
        """
        with serial.Serial(
            self.com,
            self.speed,
            serial.EIGHTBITS,
            serial.PARITY_NONE,
            serial.STOPBITS_ONE,
        ) as ser:
            logging.debug("SEND: %s (%s)", req, repr_byte_arr(req))
            ser.write(req)
            time.sleep(WAIT_RESPONSE)
            out = ser.read_all()
            logging.debug("READ: %s (%s)", out, repr_byte_arr(out))
            reply = out
            if self.echo_mode == "enabled":
                echo = out[: len(req)]
                e_i = int.from_bytes(echo, byteorder="big", signed=False)
                r_i = int.from_bytes(req, byteorder="big", signed=False)
                if e_i == r_i and hash(echo) == hash(req):
                    logging.debug("stripping echo: %s (%s)", echo, repr_byte_arr(echo))
                reply = ""
                try:
                    reply = out[len(req) :]
                except IndexError:
                    logging.error("no reply after stripping echo")
                    if len(out) == len(req):
                        raise
            return reply

    def detect_serial_echo_mode(self):
        logging.info("Detecting serial echo mode...")
        reqs = [
            MercuryRequest(
                random.choice(MercuryADDR.UNICAST_SPACE), MercuryOPS.TEST
            ).value
            for _ in range(10)
        ]
        with serial.Serial(
            self.com,
            self.speed,
            serial.EIGHTBITS,
            serial.PARITY_NONE,
            serial.STOPBITS_ONE,
        ) as ser:
            for req in reqs:
                ser.write(req)
                time.sleep(WAIT_RESPONSE)
                out = ser.read_all().lstrip()
                req_repr = repr_byte_arr(req)
                out_repr = repr_byte_arr(out)
                logging.debug(f"send: {req} ({req_repr}), recv: {out} ({out_repr})")
                if len(req) > len(out) or repr_byte_arr(out[:len(req)]) != req_repr:
                    logging.info("Echo not found")
                    return "disabled"
        logging.info("Found evidence of echo on all counts")
        return "enabled"

    def test_connection(self):
        """
        Runs a connection test for the specified address
        """
        req = MercuryRequest(self.addr, MercuryOPS.TEST).value
        try:
            reply = MercuryReply(self.communicate(req))
        except Exception as ex:
            logging.fatal("Connection failed to %s", self.addr)
            raise MercuryConnectionException("Connection failure") from ex
        logging.debug("connection test reply : %s", {reply.raw_data})
        return reply.is_ok()

    def logout(self):
        """
        Explicitly Closes communication channel
        """
        req = MercuryRequest(self.addr, MercuryOPS.CLOSE).value
        reply = MercuryReply(self.communicate(req))
        logging.debug("connection close reply: %s", reply.raw_data)
        return reply.is_ok()

    def login(self, user=MercuryLEVEL.ADMIN, psw=None):
        """
        Opens Communications Channel with specified user code and password
        """
        if psw is None:
            psw = MercuryPASSWORD.get(user, 0)
        psw_s = str(psw).zfill(6)
        psw_e = bytes([int(d) for d in psw_s])
        req = MercuryRequest(self.addr, MercuryOPS.OPEN, user + psw_e).value
        data = self.communicate(req)
        if data:
            reply = MercuryReply(data)
            logging.debug("login reply: %s", reply.raw_data)
            return reply.is_ok()
        else:
            return False
