"""signature handling"""
from __future__ import annotations

import binascii
import datetime
import enum
import os
import math
import logging
from typing import Tuple, Mapping, Callable

from openpgp.common import (
    Context, Signature, SignatureType, PublicKeyAlgorithm, HashAlgorithm,
)
from openpgp import helpers
from openpgp import rsa

logger = logging.getLogger(__name__)


class SignatureError(Exception):
    """problem while processing a signature"""


def parse_signature(context: Context, data: bytes) -> Context:
    parsers: Mapping[int, Callable[[Context, bytes], Signature]] = {
        4: parse_v4_signature,
    }
    try:
        sig_parser = parsers[data[0]]
    except KeyError:
        logger.error(f'unknown signature version {data[0]}')
        return context
    try:
        sig = sig_parser(context, data)
    except SignatureError:
        pass
    else:
        context.temp.sig_reference.signatures.add(sig)
    return context


def parse_v4_signature(context: Context, data: bytes) -> Signature:
    sig = Signature()
    sig.type = SignatureType(data[1])
    sig.public_key_algo = PublicKeyAlgorithm(data[2])
    sig.hash_algo = HashAlgorithm(data[3])
    context.temp.signatures.append(sig)
    hashed_init = data[:4]
    context, hashed_subpacket_bytes, data = \
        parse_v4sig_subpackets(context, data[4:], sig.hashed_subpackets)
    context, _, data = parse_v4sig_subpackets(context, data, sig.unhashed_subpackets)
    sig = context.temp.signatures.pop()
    sig.check_bytes = data[:2]
    context.temp.sig_trailer = hashed_init + hashed_subpacket_bytes
    data = data[2:]
    if sig.public_key_algo.name in ('RSA', 'RSA_SIGN'):
        sig.value, data = helpers.read_mpi(data)
        assert not data
    else:
        logger.error(str(sig.public_key_algo) + ' not supported')
        raise SignatureError
    if not verify_v4_signature(context, sig):
        logger.error('invalid signature')
        raise SignatureError
    return sig


def write_v4_signature(sig: Signature) -> bytes:
    """convert a Signature object to bytes representing the packet body"""
    r = [4, sig.type.value, sig.public_key_algo.value, sig.hash_algo.value]
    r += get_subpacket_bytes(sig, sig.hashed_subpackets)
    r += get_subpacket_bytes(sig, sig.unhashed_subpackets)
    r.append(sig.check_bytes)
    return b''.join(r)


def get_subpacket_bytes(sig: Signature, packets: list) -> bytes:
    """get a signature's subpackets"""
    r = []
    for packet in packets:
        new_data = packet.write(sig)
        r.append(helpers.write_new_packet_length(len(new_data), include_partial=False))
        r.append(bytes([packet.value | (2**8 * (packet in sig.critical_subpackets))]))
        r.append(new_data)
    return b''.join((len(r).to_bytes(2, 'big'), *r))


def get_v4_signature_data(context: Context, sig_type: SignatureType) -> bytes:
    if sig_type is SignatureType.BINARY:
        data = context.messages[-1].data
        context.temp.sig_reference = context.messages[-1]
    elif sig_type is SignatureType.TEXT:
        data = context.messages[-1].data.replace(os.linesep.encode(), b'\r\n')
        context.temp.sig_reference = context.messages[-1]
    elif sig_type.name.endswith('_UID'):
        key = context.temp.last_key
        data = key.fingerprint_data
        data += context.temp.last_user_data
        context.temp.sig_reference = key
    elif sig_type is SignatureType.SUBKEY_BIND:
        key = context.temp.last_key
        data = key.parent.fingerprint_data
        data += key.fingerprint_data
        context.temp.sig_reference = key
    else:
        raise NotImplementedError(f"can't handle {sig_type} signatures")
    data += context.temp.sig_trailer
    data += b'\x04\xff' + len(context.temp.sig_trailer).to_bytes(4, 'big')
    return data


def verify_v4_signature(context: Context, signature: Signature) -> bool:
    def rsa_verify(data, sig, key):
        sig_bytes = sig.to_bytes(math.ceil(sig.bit_length()/8), 'big')
        return rsa.rsassa_pkcs1_v1_5_verify(data, sig_bytes, key)

    verify_func = {
        'RSA': rsa_verify,
        'RSA_SIGN': rsa_verify,
    }[signature.public_key_algo.name]
    try:
        sign_key = context.keys[signature.issuer]
    except KeyError:
        logger.warning(f'unknown signing key {signature.issuer}')
        raise SignatureError

    if signature.type is SignatureType.SUBKEY_BIND:
        issue_key = context.keys.get(signature.issuer)
        if issue_key != context.temp.last_key.parent:
            logger.error(
                f'Subkey signature {signature!r} by unexpected key {issue_key!r}.')
            raise SignatureError
    elif signature.type in (SignatureType.BINARY, SignatureType.TEXT):
        last_message_type = context.messages[-1].data_type
        if last_message_type.name != signature.type.name:
            logger.error(f'Unexpected {signature.type} for {last_message_type} message.')
            raise SignatureError

    data = get_v4_signature_data(context, signature.type)
    hashed = signature.hash_algo.func(data)
    if hashed[:2] != signature.check_bytes:
        return False
    hashed = signature.hash_algo.prefix + hashed
    return verify_func(hashed, signature.value, sign_key.key_data)


def parse_v4sig_subpackets(context: Context, data: bytes, packet_list: list) \
        -> Tuple[Context, bytes, bytes]:
    length = data[0] * 256 + data[1]
    assert length < len(data) - 2
    acc_data = data[:length+2]
    data = data[2:]
    remainder = data[length:]
    data = data[:length]
    while data:
        context, data = parse_v4sig_subpacket(context, data, packet_list)
    return context, acc_data, remainder


def parse_v4sig_subpacket(context: Context, data: bytes, packet_list: list) \
        -> Tuple[Context, bytes]:
    length_length, length = helpers.read_new_packet_length(data)
    data, remainder = data[length_length:length], data[length:]
    packet_tag = data[0]
    packet_data = data[1:]
    packet_tag, critical = packet_tag & ~2**8, packet_tag & 2**8
    packet_type = SignatureSubPacketType(packet_tag)
    parser = packet_type.parse
    if critical:
        context.temp.signatures[-1].critical_subpackets.append(packet_tag)
    if parser is None:
        logger.debug(f'skipping {packet_type}')
        if critical:
            logger.warning('critical unimplemented signature subpacket {packet_type}')
    elif packet_type is SignatureSubPacketType.SIG_EMBED:
        logger.debug(f'handling {packet_type}')
        context = parse_signature(context, packet_data)
    else:
        logger.debug(f'handling {packet_type}')
        packet_list.append(packet_type)
        parser(context.temp.signatures[-1], packet_data)
    return context, remainder


def parse_issuer(sig: Signature, data: bytes):
    data = binascii.hexlify(data).decode()
    if sig.issuer is None:
        sig.issuer = data
    elif sig.issuer[-16:] != data:
        logger.warning('conflicting issuer data')


def write_issuer(sig: Signature):
    return binascii.unhexlify(sig.issuer[-16:])


def parse_issuer_fp(sig: Signature, data: bytes):
    if data[0] != 4:
        logger.error(f"can't handle V{data[0]} keys")
        return
    data = binascii.hexlify(data[1:]).decode()
    if sig.issuer is not None:
        if ((len(sig.issuer) == 16 and sig.issuer != data[-16:])
                or sig.issuer != data):
            logger.warning('conflicting issuer data')
    sig.issuer = data


def write_issuer_fp(sig: Signature):
    assert len(sig.issuer) == 40
    return b'\x04' + binascii.unhexlify(sig.issuer)


def _time_helper(field_name):
    return (
        lambda sig, d: setattr(sig, field_name, helpers.time_from_bytes(d)),
        lambda sig: helpers.time_to_bytes(getattr(sig, field_name)),
    )


def _bool_helper(field_name):
    return (
        lambda sig, d: setattr(sig, field_name, bool(d[0])),
        lambda sig: b'\x01' if getattr(sig, field_name) else b'\x00',
    )


def _text_helper(field_name):
    return (
        lambda sig, d: setattr(sig, field_name, d.decode()),
        lambda sig: getattr(sig, field_name).encode(),
    )


class SignatureSubPacketType(enum.Enum):
    def __new__(cls, key, parse=None, write=None):
        assert (parse is not None) == (write is not None)
        self = object.__new__(cls)
        self._value_ = key
        self.parse = parse
        self.write = write
        return self

    @classmethod
    def _missing_(cls, value):
        logger.debug('unknown subpacket %s', value)
        return cls.UNKNOWN

    UNKNOWN = -1
    CREATE_TIME = (2, *_time_helper('creation_time'))
    EXPIRE_TIME = (
        3,
        lambda sig, d: setattr(sig, 'lifetime', datetime.timedelta(
            seconds=int.from_bytes(d, 'big'))),
        lambda sig: (sig.lifetime.total_seconds()).to_bytes(4, 'big'),
    )
    EXPORTABLE_CERT = (4, *_bool_helper('exportable'))
    TRUST = 5  # NO
    REGEX = 6  # NO
    REVOCABLE = (7, *_bool_helper('revocable'))
    KEY_EXPIRE = 9  # NO
    PREF_SYMM_ALGO = 11  # NO
    REVOKE_KEY = 12  # NO
    ISSUER = 16, parse_issuer, write_issuer
    NOTATION_DATA = 20  # NO
    PREF_HASH_ALGO = 21  # NO
    PREF_COMPRESSION = 22  # NO
    KEY_SERVER_PREFS = 23  # NO
    PREF_KEY_SERVER = 24  # NO
    PRIMARY_USER_ID = 25  # NO
    POLICY_URI = (26, *_text_helper('policy_uri'))
    KEY_FLAGS = 27  # MAYBE
    SIGNER_USER_ID = (28, *_text_helper('user_id'))
    REVOKE_REASON = 29  # NO
    FEATURES = 30  # NO
    SIG_TARGET = 31  # NO
    SIG_EMBED = 32  # implemented externally
    ISSUER_FINGERPRINT = 33, parse_issuer_fp, write_issuer_fp  # draft-bis-09
