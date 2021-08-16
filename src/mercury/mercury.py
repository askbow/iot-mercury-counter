import argparse
import serial
import struct
import time
import logging

from collections import namedtuple

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

WAIT_RESPONSE = .150

class MercuryADDR:
    UNIVERSAL = 0x00
    UNICAST_SPACE = range(0x01, 0xf1)
    BROADCAST = 0xfe
    RESERVED = range(0xf1, 0xff+1)


class MercuryOPS:
    TEST = 0
    OPEN = 1
    CLOSE = 2


class MercuryLEVEL:
    USER = b'\x01'
    ADMIN = b'\x02'


class MercuryREPLY:
    OK = 0
    BAD_COMMAND = 1
    INTERNAL_ERROR = 2
    UNAUTHORIZED = 3
    CLOCK_SYNC = 4
    LOGIN_REQUIRED = 5

MercuryREPLYStatuses = {
    MercuryREPLY.OK: 'Success',
    MercuryREPLY.BAD_COMMAND: 'Bad command or operands',
    MercuryREPLY.INTERNAL_ERROR: 'Counter Internal error',
    MercuryREPLY.UNAUTHORIZED: 'Current level insufficient fro the operation',
    MercuryREPLY.CLOCK_SYNC: 'Internal clock already sunchrnized',
    MercuryREPLY.LOGIN_REQUIRED: 'Operation requires open channel',
}

MercurySPEEDS = (300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)

MercuryPASSWORD = {
    MercuryLEVEL.USER : 111111,
    MercuryLEVEL.ADMIN: 222222,
}


def progressbar(position, max, end=''):
    '''
    Draws a progress bar in CLI
    '''
    max_v = max - 1
    progressbarlen = 50
    progressbarcurpos = int(position / max_v * progressbarlen)
    progressbarpercent = int(position / max_v * 100)
    print(f'\r[ {"#" *  progressbarcurpos}{"-" * (progressbarlen-progressbarcurpos)} ] {progressbarpercent}%\t{end}', end='', flush=True)


def crc16(data: bytes):
    '''
    CRC16-MODBUS adapted from Mercury Documentation
    '''
    srCRCHi = bytearray([
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
        0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
        0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
        0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40
    ])
    srCRCLo = bytearray([
        0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
        0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09, 0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
        0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12,0x13, 0xD3,
        0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
        0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A, 0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
        0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
        0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
        0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F, 0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
        0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
        0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
        0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C, 0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
        0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
        0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80, 0x40
    ])
    InitCRC = 0xFFFF
    def UpdCRC(C, oldCRC):
        arrCRC = bytearray(list(oldCRC.to_bytes(2, byteorder='big')))
        i = arrCRC[1] ^ C
        arrCRC[1] = arrCRC[0] ^ srCRCHi[i]
        arrCRC[0] = srCRCLo[i]
        return int.from_bytes(arrCRC, byteorder='big', signed=False)
    
    crc = InitCRC
    for d in data:
        crc = UpdCRC(d, crc)
    first = crc // 256
    second = crc % 256
    return bytearray([second, first])


class MercuryRequest:
    def __init__(self, address, request_code, args=None):
        self.address = address
        self.request_code = request_code
        self.params = args
        self._value = None
        self.format = '<BB'

    def __len__(self):
        return len(self.value)

    def append_checksum(self, data):
        crc = crc16(data)
        return data + crc

    @property
    def value(self):
        if self._value is None:
            value = struct.pack(
                self.format,
                self.address,
                self.request_code,
            )
            if self.params is not None:
                value += self.params
            self._value = self.append_checksum(value)
        return self._value


class MercuryReply:
    def __init__(self, data, req_rep=False):
        self.header_offset = 1
        if req_rep:
            self.header_offset += 1
        self._data = data
        self.format = ''.join(['<B', 'B'*(len(data)-self.header_offset-2), 'H'])
        
        self.fields = [d for d in struct.unpack(self.format, data)]
        
        if not self.verify_checksum():
            crc = crc16(self._data[:-2])
            crc_d = self.checksum
            logging.warning('bad checksum in {data}: {crc_d}, expected {crc}')
        if not self.is_ok():
            logging.error(MercuryREPLYStatuses.get(self.status, f'Unknow error: {self.status}'))
    
    def __len__(self):
        return len(self.data)
        
    def verify_checksum(self):
        return crc16(self._data[:-2]) == self.checksum
    
    @property
    def checksum(self):
        return self.fields[-1]
    
    @property
    def addr(self):
        return self.fields[0]
    
    @property
    def raw_data(self):
        return self._data
    
    @property
    def parsed_data(self):
        return self.fields[self.header_offset:-1]

    @property
    def status(self):
        return self.parsed_data[0] & 0x07
    
    def is_ok(self):
        return self.status == MercuryREPLY.OK


class MercuryDriver:
    def __init__(self, com, addr, speed=9600):
        self.com = com
        assert speed in MercurySPEEDS
        self.speed = speed
        assert addr in MercuryADDR.UNICAST_SPACE or addr == MercuryADDR.UNIVERSAL
        self.addr = addr

    def communicate(self, req):
        with serial.Serial(self.com, self.speed, serial.EIGHTBITS, serial.PARITY_NONE, serial.STOPBITS_ONE) as ser:
            logging.debug(f'SEND: {req}')
            ser.write(req)
            time.sleep(WAIT_RESPONSE)
            out = ser.read_all()
            logging.debug(f'READ: {out}')
            reply = out
            if len(out) > len(req):
                echo = out[:len(req)]
                e_i = int.from_bytes(echo, byteorder='big', signed=False)
                r_i = int.from_bytes(req, byteorder='big', signed=False)
                if e_i == r_i and hash(echo) == hash(req):
                   logging.debug(f'stripping echo: {echo}')
                reply = ''
                try:
                    reply = out[len(req):]
                except Exception:
                    logging.error(f'no reply after stripping echo')
                    raise
            return reply
        
    def test_connection(self):
        req = MercuryRequest(self.addr, MercuryOPS.TEST).value
        try:
            reply = MercuryReply(self.communicate(req))
        except:
            logging.fatal(f'Connection failed to {self.addr}')
            raise Exception('Connection failure')
        logging.debug(f'connection test reply : {reply}')
        return reply.is_ok()
    
    def logout(self):
        req = MercuryRequest(self.addr, MercuryOPS.CLOSE).value
        reply = MercuryReply(self.communicate(req))
        logging.debug(f'connection close reply: {reply}')
        return reply.is_ok()
    
    def login(self, user=MercuryLEVEL.ADMIN, psw=None):
        if psw is None:
           psw = MercuryPASSWORD.get(user, 0)
        psw_s = str(psw).zfill(6)
        psw_e = bytes([int(d) for d in psw_s])
        req = MercuryRequest(sn, MercuryOPS.OPEN, user + psw_e).value
        reply = MercuryReply(self.communicate(req))
        logging.debug(f'login reply: {reply}')
        return reply.is_ok()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('serial', type=str,  nargs='?', default=0, help='Serial port. e.g. USB4')
    parser.add_argument('sn', type=int,  nargs='?', default=MercuryADDR.UNIVERSAL, help='address')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    com = args.serial
    sn = args.sn
    
    counter = MercuryDriver(com, sn)
    counter.test_connection()
    counter.logout()

    passwords = range(0, 1000000)
    MAX = len(passwords)
    logging.info(f'Trying {MAX} passwords:')
    progressbar(0, MAX, '')
    for pos, psw in enumerate(passwords):
        psw_s = str(psw).zfill(6)
        progressbar(pos, MAX, psw_s)
        if counter.login(psw=psw):
            logging.info(f'Login successful with {psw_s}')
            break
    counter.logout()
    logging.info('Done.')


if __name__ == '__main__':
    main()