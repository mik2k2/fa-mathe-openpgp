"""OpenPGP messages"""
from __future__ import annotations

import binascii
import copy
import functools
import logging
import math
import os
import hashlib
import types
from typing import Tuple, Union

from openpgp.common import (
    Context,
    PublicKeyAlgorithm, CompressionAlgorithm, SymmetricAlgorithm,
    Key, Message, PacketType, DataType
)
from openpgp import signature
from openpgp import rsa
from openpgp import openpgp_cfb
from openpgp import helpers

logger = logging.getLogger(__name__)

parsers = {
    PacketType.SIGNATURE: signature.parse_signature,
    # modification detection directly reads the last bytes
    PacketType.MOD_DETECT: lambda c, d: c,
}


def parser_function(packet: PacketType = None, wrap: types.FunctionType = None):
    def wrapper(f):
        nonlocal packet
        if packet is None:
            packet = getattr(PacketType, f.__name__.replace('parse_', '').upper())
        if wrap is None:
            parsers[packet] = f
        else:
            parsers[packet] = functools.wraps(f)(wrap(f))
        return f

    if isinstance(packet, types.FunctionType):
        # called as @parser_function without ()
        func = packet
        packet = None
        return wrapper(func)
    else:
        # called as @parser_function() with ()
        return wrapper


def get_session_key_msg(algo: SymmetricAlgorithm, key: bytes) -> bytes:
    return b''.join((
        bytes([algo.value]),
        key,
        (sum(key) % 2**16).to_bytes(2, 'big'),
    ))


def read_session_key_msg(data: bytes) \
        -> Union[Tuple[None, None], Tuple[SymmetricAlgorithm, bytes]]:
    algo = SymmetricAlgorithm(data[0])
    key = data[1:-2]
    checksum = int.from_bytes(data[-2:], 'big')
    if checksum != sum(key) % 2**16:
        logger.error('Wrong checksum when reading session key')
        return None, None
    return algo, key


def parse(context: Context, data: bytes) -> Context:
    """parse the data"""
    while data:
        first_byte = data[0]
        assert first_byte & 0b10000000, first_byte
        if first_byte & 0b01000000:
            context, data = parse_new_packet(context, data)
        else:
            context, data = parse_old_packet(context, data)
    return context


def parse_new_packet(context: Context, data: bytes) -> Tuple[Context, bytes]:
    assert data[0] & 0b01000000, data[0]
    tag = data[0] & 0b00111111
    packet_type = PacketType(tag)
    parser = parsers.get(packet_type)
    try:
        packet_data, remainder = helpers.split_new_packet(data[1:])
    except ValueError:
        logger.error(f'Packet {packet_type} uses an unsupported partial length. '
                     'Impossible to read any further data from this source.')
        return context, b''
    if parser is None:
        logger.info(f'skipping {packet_type} (new format)')
        return context, remainder
    else:
        logger.debug(f'handling {packet_type} (new format)')
        return parser(context, packet_data), remainder


def parse_old_packet(context: Context, data: bytes) -> Tuple[Context, bytes]:
    assert not data[0] & 0b01000000, data[0]
    tag = (data[0] & 0b00111100) >> 2
    packet_type = PacketType(tag)
    parser = parsers.get(packet_type)
    length_length = data[0] & 0b00000011
    data = data[1:]
    if length_length == 3:
        length_length = 0
        length = len(data)
    else:
        length_length = 2 ** length_length
        length = int.from_bytes(data[:length_length], 'big') + length_length

    packet_data = data[length_length:length]
    remainder = data[length:]
    if parser is None:
        logger.info(f'skipping {packet_type} (old format)')
        return context, remainder
    else:
        logger.debug(f'handling {packet_type} (old format)')
        return parser(context, packet_data), remainder


@parser_function
def parse_pub_sess_key(context: Context, data: bytes) -> Context:
    assert data[0] == 3, data[0]
    key_id = binascii.hexlify(data[1:9]).decode()
    algo = PublicKeyAlgorithm(data[9])
    data = data[10:]
    if algo in (PublicKeyAlgorithm.RSA, PublicKeyAlgorithm.RSA_ENCRYPT):
        value, data = helpers.read_mpi(data)
        assert not data
        if any(key_id):
            attempt_ids = [key_id]
        else:
            attempt_ids = context.keys
        for attempt_id in attempt_ids:
            try:
                secret_key = context.keys[attempt_id].secret_data
            except KeyError:
                continue
            if secret_key is None:
                continue
            e_bytes = value.to_bytes(math.ceil(secret_key[1].bit_length() / 8), 'big')
            d_bytes = rsa.rsaes_pkcs1_v1_5_decrypt(secret_key, e_bytes)
            algo = SymmetricAlgorithm(d_bytes[0])
            sess_key = d_bytes[1:-2]
            if sum(sess_key) % 65536 == int.from_bytes(d_bytes[-2:], 'big'):
                break
        else:
            context.temp.failed_public_keys.append(key_id)
            return context
        context.temp.session_algo = algo
        context.temp.session_key = sess_key
    else:
        logger.error(f'{algo} not supported')
    return context


@parser_function(wrap=lambda f: (lambda *a, **kw: f(*a, **kw, is_subkey=False)[0]))
@parser_function(PacketType.PUBLIC_SUBKEY,
                 wrap=lambda f: (lambda *a, **kw: f(*a, **kw, is_subkey=True)[0]))
def parse_public_key(context: Context, data: bytes, is_subkey: bool) \
        -> Tuple[Context, bytes]:
    original_data = data
    version = data[0]
    if version != 4:
        logger.error(f'V{version} public keys not supported')
        context.temp.last_key = None
        return context, b''
    timestamp = helpers.time_from_bytes(data[1:5])
    pub_key_algo = PublicKeyAlgorithm(data[5])
    data = data[6:]
    if pub_key_algo.name.startswith('RSA'):
        n, data = helpers.read_mpi(data)
        e, data = helpers.read_mpi(data)
        key_data = (e, n)
    else:
        logger.error(f'{pub_key_algo} not supported')
        context.temp.last_key = None
        return context, b''
    if data:
        packet_data = original_data[:-len(data)]
    else:
        packet_data = original_data
    fingerprint_data = b''.join((
        b'\x99', len(packet_data).to_bytes(2, 'big'), packet_data))
    fingerprint = hashlib.sha1(fingerprint_data).hexdigest()
    if fingerprint in context.keys:
        context.temp.last_key = context.keys[fingerprint]
        return context, data
    key_id = fingerprint[-16:]
    key = Key(
        type=pub_key_algo,
        key_data=key_data,
        fingerprint=fingerprint,
        fingerprint_data=fingerprint_data,
        timestamp=timestamp,
    )
    if is_subkey:
        key.parent = context.temp.last_key
    context.temp.last_key = key
    context.keys[fingerprint] = key
    conflict_key = context.keys.get(key_id)
    if conflict_key is not None and conflict_key.fingerprint != key.fingerprint:
        logger.warning(f'removing short key ID "{key_id}" because of collision'
                       f' between {key.fingerprint} and {conflict_key.fingerprint}')
        del context.keys[key_id]
    else:
        context.keys[key_id] = key
    logger.info(f'Added key {key.fingerprint}')
    return context, data


@parser_function
@parser_function(PacketType.SECRET_SUBKEY,
                 wrap=functools.partial(functools.partial, is_subkey=True))
def parse_secret_key(context: Context, data: bytes, is_subkey: bool = False) -> Context:
    context, data = parse_public_key(context, data, is_subkey)
    if context.temp.last_key is None:  # problem with public key
        return context
    pub_key = context.temp.last_key
    s2k = data[0]
    if s2k:
        logger.error('Encrypted keys not supported')
        return context
    data = data[1:]
    check = sum(data[:-2]) % 65536
    if pub_key.type.name.startswith('RSA'):
        d, data = helpers.read_mpi(data)
        data = helpers.read_mpi(helpers.read_mpi(helpers.read_mpi(data)[1])[1])[1]  # p, q, u
        n = pub_key.key_data[1]
        key_data = (d, n)
    else:
        raise AssertionError('parse_public_key handles supported algorithms')
    assert check == int.from_bytes(data, 'big'), (check, data)
    pub_key.secret_data = key_data
    return context


@parser_function
def parse_compressed(context: Context, data: bytes) -> Context:
    compression_algo = CompressionAlgorithm(data[0])
    return parse(context, compression_algo.func(data[1:]))


@parser_function
def parse_literal_data(context: Context, data: bytes) -> Context:
    data_type = DataType(data[0])
    file_name_length, data = data[1], data[2:]
    filename, data = data[:file_name_length], data[file_name_length:]
    timestamp, data = helpers.time_from_bytes(data[:4]), data[4:]
    if data_type is DataType.TEXT:
        data = data.replace(b'\r\n', os.linesep.encode())
    msg = Message(
        data=data,
        data_type=data_type,
        filename=filename,
        timestamp=timestamp,
    )
    context.messages.append(msg)
    return context


@parser_function
def parse_user_id(context: Context, data: bytes) -> Context:
    user_id = data.decode()
    key = context.temp.last_key
    if key is None:
        logger.warning('unexpected USER_ID packet')
        return context
    key.user_id = user_id
    context.temp.last_user_data = b''.join((
        b'\xb4', len(data).to_bytes(4, 'big'), data))
    return context


@parser_function
def parse_symm_data(context: Context, data: bytes, is_helper: bool = False):
    sess_key = context.temp.session_key
    sess_algo = context.temp.session_algo
    failed_public_keys = context.temp.failed_public_keys
    context.temp.session_key = context.temp.session_algo = None
    context.temp.failed_public_keys = []
    if is_helper:
        error_return = context, None
    else:
        error_return = context
    if sess_key is None:
        logger.error(f'No session key. Encrypted for: {failed_public_keys}')
        return error_return
    if sess_algo is None or not sess_algo.name.startswith('AES'):
        logger.error(f'{sess_algo} not supported')
        return error_return
    block_size = 16
    plain_data = openpgp_cfb.decrypt(data, sess_key, resync=not is_helper)
    if plain_data[block_size-2:block_size] != plain_data[block_size:block_size+2]:
        logger.error('Ciphertext integrity check failed')
        return error_return
    context = parse(context, plain_data[block_size+2:])
    if is_helper:
        return context, plain_data
    else:
        return context


@parser_function
def parse_symm_ip_data(context: Context, data: bytes) -> Context:
    assert data[0] == 1
    old_context = copy.deepcopy(context)
    context, plain_data = parse_symm_data(context, data[1:], is_helper=True)
    if plain_data is None:  # decryption error
        return context
    plain_data, expected_hash = plain_data[:-20], plain_data[-20:]
    mdc_hash = hashlib.sha1(plain_data).digest()
    if mdc_hash != expected_hash:
        logger.error('Modification detected')
        return old_context
    return context
