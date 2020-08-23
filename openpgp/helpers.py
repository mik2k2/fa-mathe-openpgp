"""Helpers"""
import datetime
import math
from typing import Tuple


def get_mpi(number: int) -> bytes:
    return (number.bit_length().to_bytes(2, 'big')
            + number.to_bytes(math.ceil(number.bit_length()/8), 'big'))


def read_mpi(data: bytes) -> Tuple[int, bytes]:
    length = math.ceil(int.from_bytes(data[:2], 'big') / 8)
    assert length <= len(data) - 2, data
    return int.from_bytes(data[2:length+2], 'big'), data[length+2:]


def time_from_bytes(timestamp):
    return datetime.datetime.fromtimestamp(int.from_bytes(timestamp, 'big'))


def time_to_bytes(time: datetime.datetime):
    return int(time.timestamp()).to_bytes(4, 'big')


def get_key(keys, substring, public):
    substring = substring.lower()
    try:
        return keys[substring]
    except KeyError:
        return next((k for k in keys.values()
                     if any(substring in uid.lower() for uid in k.user_ids)
                     and (public or k.secret_data is not None)), None)


def read_new_packet_length(data: bytes) -> Tuple[int, int]:
    """return (length-of-length, length) of a new-format packet without partial lengths"""
    length_byte = data[0]
    if length_byte < 192:
        length_length = 1
        length = length_byte
    elif length_byte < 224:
        length_length = 2
        length = (length_byte-192) * 256 + data[1] + 192
    elif length_byte < 255:
        length_length = 2
        length = (length_byte-192) * 256 + data[1] + 192
    else:
        length_length = 5
        length = int.from_bytes(data[1:5], 'big')
    length += length_length
    return length_length, length


def split_new_packet(data: bytes) -> Tuple[bytes, bytes]:
    """split a new packet into (data, other stuff)"""
    r = []
    length_byte = data[0]
    while 224 < length_byte < 255:
        # partial length
        length = 2 ** (length_byte-224) + 1
        current, data = data[1:length], data[length:]
        r.append(current)
        length_byte = data[0]
    length_length, length = read_new_packet_length(data)
    current, remainder = data[length_length:length], data[length:]
    r.append(current)
    return b''.join(r), remainder


def write_new_packet_length(length: int, include_partial: bool) -> bytes:
    """generate an appropriate new-format packet length header"""
    if length < 192:
        return bytes([length])
    elif length < (8383 if include_partial else 57344):
        length -= 192
        return bytes([(length // 256 + 192), length % 256])
    else:
        return b'\xff' + length.to_bytes(4, 'big')
