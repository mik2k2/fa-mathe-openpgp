"""enums and data containers used in multiple places"""
from __future__ import annotations

import os
import dataclasses
from typing import Dict, Any, List, Set
import hashlib
import functools
import datetime
import zlib
import enum


@dataclasses.dataclass
class TempData:
    building_signatures: List[Signature] = dataclasses.field(default_factory=list)
    last_user_id: str = None
    last_key: Key = None
    session_key: bytes = None
    failed_public_keys: List[Key] = dataclasses.field(default_factory=list)
    session_algo: SymmetricAlgorithm = None


@dataclasses.dataclass
class Context:
    messages: List[Message] = dataclasses.field(default_factory=list)
    keys: Dict[str, Key] = dataclasses.field(default_factory=dict)
    temp: TempData = dataclasses.field(default_factory=TempData, repr=False)
    unverified_signatures: List[Signature] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(unsafe_hash=True)  # data is added piece by piece
class Signature:
    reference: SignatureReference = dataclasses.field(default=None, compare=False)
    creation_time: datetime.datetime = None
    lifetime: datetime.timedelta = None
    issuer: str = None
    primary_user_id: bytes = None  # ???
    exportable: bool = True
    revocable: bool = True
    policy_uri: str = ''
    user_id: str = ''  # ???
    type: SignatureType = None
    hash_algo: HashAlgorithm = None
    public_key_algo: PublicKeyAlgorithm = None
    hashed_subpackets: list = dataclasses.field(default_factory=list, compare=False)
    unhashed_subpackets: list = dataclasses.field(default_factory=list, compare=False)
    critical_subpackets: list = dataclasses.field(default_factory=list, compare=False)
    check_bytes: bytes = dataclasses.field(default=None, repr=False)
    value: Any = dataclasses.field(default=None, repr=False)
    opaque_packet_values: dict = dataclasses.field(default_factory=dict, compare=False)

    @property
    def header(self):
        return bytes((
            4,
            self.type.value,
            self.public_key_algo.value,
            self.hash_algo.value,
        ))

    def __str__(self):
        r = [f'{self.type.name} signature ({self.public_key_algo.name}'
             f'/{self.hash_algo.name}) by {self.issuer}']
        if self.creation_time:
            r.append(f'created {self.creation_time}')
        if self.lifetime:
            r.append(f'lifetime {self.lifetime}')
        r.append(f'{"not "*(not self.exportable)}exportable')
        r.append(f'{"not "*(not self.revocable)}revocable')
        if self.policy_uri:
            r.append(f'policy: {self.policy_uri}')
        return ', '.join(r)


@dataclasses.dataclass
class Key:
    type: PublicKeyAlgorithm
    key_data: tuple
    fingerprint: str
    fingerprint_data: bytes
    user_ids: Dict[str, Set[Signature]] = dataclasses.field(default_factory=dict)
    parent: Key = None
    secret_data: tuple = None
    timestamp: datetime.datetime = None
    signatures: Set[Signature] = dataclasses.field(default_factory=set)

    def __repr__(self):
        pairs = (f'{k}={getattr(self, k)!r}' for k in dir(self)
                 if not k.startswith('_')
                 and not k.endswith('_data'))
        secret_data = 'None' if self.secret_data is None else '<AVAILABLE>'
        return f'Key({", ".join(pairs)}, secret_data={secret_data})'

    def __str__(self):
        status = 'Public Key' if self.secret_data is None else 'Key Pair'
        basic = f'{status} {self.fingerprint}'
        user_ids = ('\n\t\t'.join(map(str, [f'UID {k!r}', *v]))
                    for k, v in self.user_ids.items())
        return '\n\t'.join(map(str, [basic, *user_ids, *self.signatures]))


@dataclasses.dataclass
class Message:
    data: bytes
    data_type: DataType
    filename: bytes
    timestamp: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    signatures: Set[Signature] = dataclasses.field(default_factory=set)

    def __str__(self):
        try:
            data = repr(self.data.decode())
        except UnicodeDecodeError:
            data = '<binary data>'
        if len(data) > 50:
            data = f'{data[:25]}...{data[-25:]}'
        meta = f"file \"{self.filename.decode(errors='replace')}\", {self.timestamp}"
        return '\n\t'.join(map(str, [data, meta, *self.signatures]))


class SignatureType(enum.Enum):
    BINARY = 0x00
    TEXT = 0x01
    STANDALONE = 0x02
    GENERIC_UID = 0x10
    PERSONA_UID = 0x11
    CASUAL_UID = 0x12
    POSITIVE_UID = 0x13
    SUBKEY_BIND = 0x18
    PRIMARY_BIND = 0x19
    OWN_KEY = 0x1F
    KEY_REVOKE = 0x20
    SUBKEY_REVOKE = 0x28
    CERT_REVOKE = 0x30
    TIMESTAMP = 0x40
    CONFIRMATION = 0x50


@dataclasses.dataclass
class SignatureReference:
    sig_data: bytes = dataclasses.field(init=False, repr=False)
    sig_set: set = dataclasses.field(init=False)
    sig_type: SignatureType = dataclasses.field(init=False)


@dataclasses.dataclass
class KeyUIDSigReference(SignatureReference):
    sig_type: SignatureType = dataclasses.field(init=True)
    key: Key
    user_id: str

    def __post_init__(self):
        uid_bytes = self.user_id.encode()
        self.sig_data = b''.join((
            self.key.fingerprint_data,
            b'\xb4',
            len(uid_bytes).to_bytes(4, 'big'),
            uid_bytes,
        ))
        self.sig_set = self.key.user_ids[self.user_id]


@dataclasses.dataclass
class SubKeySigReference(SignatureReference):
    key: Key
    sig_type = SignatureType.SUBKEY_BIND

    def __post_init__(self):
        self.sig_data = self.key.parent.fingerprint_data + self.key.fingerprint_data
        self.sig_set = self.key.signatures


@dataclasses.dataclass
class MessageSigReference(SignatureReference):
    message: Message

    def __post_init__(self):
        self.sig_set = self.message.signatures
        self.sig_type = SignatureType[self.message.data_type.name]
        if self.message.data_type is DataType.TEXT:
            self.sig_data = self.message.data.replace(os.linesep.encode(), b'\r\n')
        else:
            self.sig_data = self.message.data


class DataType(enum.Enum):
    BINARY = b'b'[0]
    TEXT = b't'[0]

    @classmethod
    def _missing_(cls, value):
        """seems to be the only way to to this..."""
        if value == b'u'[0]:
            return cls.TEXT
        else:
            raise ValueError(f'{value} is not a valid {cls.__name__}')


class PacketType(enum.Enum):
    PUB_SESS_KEY = 1
    SIGNATURE = 2
    SYMM_SESS_KEY = 3
    OP_SIGNATURE = 4
    SECRET_KEY = 5
    PUBLIC_KEY = 6
    SECRET_SUBKEY = 7
    COMPRESSED = 8
    SYMM_DATA = 9
    MARKER = 10
    LITERAL_DATA = 11
    TRUST = 12
    USER_ID = 13
    PUBLIC_SUBKEY = 14
    USER_ATTRIBUTE = 17
    SYMM_IP_DATA = 18
    MOD_DETECT = 19


class HashAlgorithm(enum.Enum):
    def __new__(cls, key, prefix):
        inst = object.__new__(cls)
        inst._value_ = key
        inst.func = lambda x: getattr(hashlib, inst.name.lower())(x).digest()
        inst.prefix = prefix
        return inst

    SHA1 = 2, b'0!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14'
    SHA224 = 11, b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x04\x05\x00\x04\x1c'
    SHA256 = 8, b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 '
    SHA384 = 9, b'0A0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\x040'
    SHA512 = 10, b'0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\x04@'


class SymmetricAlgorithm(enum.Enum):
    PLAIN = 0
    IDEA = 1
    TRIPLEDES = 2
    CAST5 = 3
    BLOWFISH = 4
    AES128 = 7
    AES192 = 8
    AES256 = 9
    TWOFISH = 10


class PublicKeyAlgorithm(enum.Enum):
    RSA = 1
    RSA_ENCRYPT = 2
    RSA_SIGN = 3
    ELGAMAL = 16
    DSA = 17


class CompressionAlgorithm(enum.Enum):
    def __new__(cls, key, func):
        inst = object.__new__(cls)
        inst._value_ = key
        inst.func = func
        return inst

    UNCOMPRESSED = 0, lambda d: d
    ZIP = 1, functools.partial(zlib.decompress, wbits=-zlib.MAX_WBITS)
    ZLIB = 2, functools.partial(zlib.decompress, wbits=zlib.MAX_WBITS)
    BZIP2 = 3, functools.partial(zlib.decompress, wbits=zlib.MAX_WBITS | 16)
