"""Create binary representations of OpenPGP packages"""
import binascii
import hashlib
import os
import secrets
import typing
import logging

from openpgp import signature, openpgp_cfb, rsa
from openpgp import helpers
from openpgp.common import PacketType, Key, PublicKeyAlgorithm, SymmetricAlgorithm, \
    Message, DataType, Signature

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """encryption could not be performed"""


def add_header(packet_type: PacketType, packet_data: bytes) -> bytes:
    """add a new-format packet header"""
    first_byte = packet_type.value | 0b11000000
    length = helpers.write_new_packet_length(len(packet_data), include_partial=True)
    return bytes([first_byte, *length, *packet_data])


def write_signatures(signatures: typing.Iterable[Signature]) -> bytes:
    """generate packets for all the signatures"""
    return b''.join(add_header(PacketType.SIGNATURE, sig_data)
                    for sig_data in map(signature.write_v4_signature, signatures))


def encrypt_session_key(symmetric_byte: int,
                        session_key: bytes,
                        recipient_keys: typing.Iterable[Key]
                        ) -> bytes:
    """generate a appropriate PUB_SESS_KEY packets"""
    r = []
    checksum = divmod(sum(session_key) % 65536, 256)
    session_key = bytes([symmetric_byte, *session_key, *checksum])
    for public_key in recipient_keys:
        key_id = binascii.unhexlify(public_key.fingerprint[-16:])
        packet = [3, *key_id, public_key.type.value]
        if public_key.type in (PublicKeyAlgorithm.RSA_ENCRYPT, PublicKeyAlgorithm.RSA):
            encrypted = rsa.rsaes_pkcs1_v1_5_encrypt(public_key.key_data, session_key)
            packet += helpers.get_mpi(int.from_bytes(encrypted, 'big'))
        else:
            logger.error(f'Unsupported public-key encryption algorithm {public_key.type}.'
                         f' Failed to encrypt message to {public_key.fingerprint}')
            continue
        r += add_header(PacketType.PUB_SESS_KEY, bytes(packet))
    return bytes(r)


def encrypt_data(data: bytes, keys: typing.Iterable[Key], algo: SymmetricAlgorithm) \
        -> bytes:
    """Encrypt data for given keys. Return PUB_SESS_KEY and SYMM_IP_DATA packets"""
    block_size = 16
    try:
        key_size = {
            SymmetricAlgorithm.AES128: 16,
            SymmetricAlgorithm.AES192: 24,
            SymmetricAlgorithm.AES256: 32,
        }[algo]
    except KeyError:
        logger.error(f'unsupported secret key algorithm {algo}')
        return b''
    session_key = secrets.token_bytes(key_size)
    homebrew_iv = secrets.token_bytes(block_size)
    homebrew_iv += homebrew_iv[-2:]
    data = homebrew_iv + data
    data += b'\xd3\x14'  # modification detection
    data += hashlib.sha1(data).digest()
    encrypted = openpgp_cfb.encrypt(data, session_key, resync=False)
    symm_ip_data = add_header(PacketType.SYMM_IP_DATA, b'\x01' + encrypted)
    pub_sess_keys = encrypt_session_key(algo.value, session_key, keys)
    return pub_sess_keys + symm_ip_data


def write_message(message: Message) -> bytes:
    """create packets for a message object"""
    if len(message.filename) > 255:
        raise OverflowError('file name too large')
    if message.data_type is DataType.BINARY:
        data = message.data
    elif message.data_type is DataType.TEXT:
        data = message.data.replace(os.linesep.encode(), b'\r\n')
    else:
        raise AssertionError(f'unexpected message.data_type {message.data_type}')
    r = [message.data_type.value, len(message.filename), *message.filename]
    r += helpers.time_to_bytes(message.timestamp)
    r += data
    return (add_header(PacketType.LITERAL_DATA, bytes(r))
            + write_signatures(message.signatures))
