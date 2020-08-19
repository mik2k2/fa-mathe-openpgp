"""AES implementation (don't actually use this)"""
import typing


ByteMatrix = typing.MutableSequence[typing.MutableSequence[int]]


def xtime(num: int) -> int:
    """perform the xtime operation"""
    num <<= 1
    if num & 0x100:
        num ^= 0x11b
    return num


def byte_mul(a: int, b: int) -> int:
    """implement byte multiplication"""
    r = 0
    for mul in (1, 2, 4, 8, 16, 32, 64, 128):
        if b & mul:
            r ^= a
        a = xtime(a)
    return r


def vector_mul(va: typing.Sequence[int], vb: typing.Sequence[int]
               ) -> typing.Sequence[int]:
    """implement bte vector multiplication"""
    new = [0] * 4
    for i, a in enumerate(va):
        for j, b in enumerate(vb):
            new[(i+j)%4] ^= byte_mul(a, b)
    return new


def to_matrix(data: typing.Sequence[int]) -> ByteMatrix:
    """transform linear bytes to a 4x{4,6,8} matrix"""
    return list(map(list, zip(*([iter(data)]*4))))


def from_matrix(data: ByteMatrix) -> typing.Iterable[int]:
    """transform a matrix to linear data"""
    for column in data:
        for value in column:
            yield value


def expand_key(key: bytes):
    """expand the given key. yield the round keys
        function shamelessly copied from the specification
    """
    assert len(key) in (16, 24, 32)

    def do_SubWord(word):
        return [S_BOX[x] for x in word]

    def do_RotWord(word):
        return word[1:] + word[:1]

    def seq_xor(seq_a, seq_b):
        return [a^b for a, b in zip(seq_a, seq_b)]

    Nb = 4
    Nk = len(key) // 4
    Nr = Nk + 6
    W = [None] * (Nb*(Nr+1))

    for i in range(Nk):
        W[i] = key[4*i:4*(i+1)]

    RC = 1
    for i in range(Nk, Nb*(Nr+1)):
        Rcon = (RC, 0, 0, 0)
        temp = W[i-1]
        if i % Nk == 0:
            temp = seq_xor(do_SubWord(do_RotWord(temp)), Rcon)
            RC *= 2
            if RC > 255:
                RC ^= M_POLYNOMIAL
        elif Nk > 6 and i % Nk == 4:
            temp = do_SubWord(temp)
        W[i] = seq_xor(W[i-Nk], temp)

    return zip(*([iter(W)]*4))


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """encrypt a block"""
    Nk = len(key) // 4
    Nr = Nk + 6
    state = to_matrix(plaintext)
    key = iter(expand_key(key))

    do_AddRoundKey(state, next(key))
    for i in reversed(range(Nr)):
        do_SubBytes(state, S_BOX)
        do_ShiftRows(state, 1)
        if i:
            do_MixColumns(state, C_VECTOR)
        do_AddRoundKey(state, next(key))

    return bytes(from_matrix(state))


def decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """decrypt a block"""
    Nk = len(key) // 4
    Nr = Nk + 6
    state = to_matrix(ciphertext)
    key = reversed(tuple(expand_key(key)))

    do_AddRoundKey(state, next(key))
    for i in reversed(range(Nr)):
        do_ShiftRows(state, -1)
        do_SubBytes(state, INV_S_BOX)
        do_AddRoundKey(state, next(key))
        if i:
            do_MixColumns(state, D_VECTOR)

    return bytes(from_matrix(state))


def do_SubBytes(state: ByteMatrix, s_box: typing.Sequence[int]):
    """perform the SubBytes operation with the given s-box"""
    for vec in state:
        for i in range(len(vec)):
            vec[i] = s_box[vec[i]]


def do_ShiftRows(state: ByteMatrix, direction: int):
    """perform the ShiftRows operation for en-(1) or de(-1)cryption"""
    for row in range(4):  # 4 = Nb
        # for Nb == 4, row number == shift number
        amount = row * direction
        row_values = [state[i][row] for i in range(4)]  # 4 = len(state)
        row_values = row_values[amount:] + row_values[:amount]
        for i, val in enumerate(row_values):
            state[i][row] = val


def do_MixColumns(state: ByteMatrix, mul_vector: typing.Sequence[int]):
    """perform the MixColumns operation"""
    for i, vec in enumerate(state):
        state[i] = vector_mul(vec, mul_vector)


def do_AddRoundKey(state: ByteMatrix, key: ByteMatrix):
    """perform the AddRoundKey operation"""
    for text_vec, key_vec in zip(state, key):
        for i, (text, key) in enumerate(zip(text_vec, key_vec)):
            text_vec[i] = text ^ key


M_POLYNOMIAL = 0b100011011
C_VECTOR = (2, 1, 1, 3)
D_VECTOR = (0xe, 9, 0xd, 0xb)
# get these nice representations with
# print("'\n    b'".join(map(''.join, zip(*([iter(''.join(map('\\x{:0=2x}'.format, s_box)))]*(4*16))))))
S_BOX = (
    b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76'
    b'\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0'
    b'\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15'
    b'\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75'
    b'\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84'
    b'\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf'
    b'\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8'
    b'\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2'
    b'\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73'
    b'\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb'
    b'\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79'
    b'\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08'
    b'\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a'
    b'\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e'
    b'\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf'
    b'\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16'
)
INV_S_BOX = (
    b'\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb'
    b'\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44\xc4\xde\xe9\xcb'
    b'\x54\x7b\x94\x32\xa6\xc2\x23\x3d\xee\x4c\x95\x0b\x42\xfa\xc3\x4e'
    b'\x08\x2e\xa1\x66\x28\xd9\x24\xb2\x76\x5b\xa2\x49\x6d\x8b\xd1\x25'
    b'\x72\xf8\xf6\x64\x86\x68\x98\x16\xd4\xa4\x5c\xcc\x5d\x65\xb6\x92'
    b'\x6c\x70\x48\x50\xfd\xed\xb9\xda\x5e\x15\x46\x57\xa7\x8d\x9d\x84'
    b'\x90\xd8\xab\x00\x8c\xbc\xd3\x0a\xf7\xe4\x58\x05\xb8\xb3\x45\x06'
    b'\xd0\x2c\x1e\x8f\xca\x3f\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8a\x6b'
    b'\x3a\x91\x11\x41\x4f\x67\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6\x73'
    b'\x96\xac\x74\x22\xe7\xad\x35\x85\xe2\xf9\x37\xe8\x1c\x75\xdf\x6e'
    b'\x47\xf1\x1a\x71\x1d\x29\xc5\x89\x6f\xb7\x62\x0e\xaa\x18\xbe\x1b'
    b'\xfc\x56\x3e\x4b\xc6\xd2\x79\x20\x9a\xdb\xc0\xfe\x78\xcd\x5a\xf4'
    b'\x1f\xdd\xa8\x33\x88\x07\xc7\x31\xb1\x12\x10\x59\x27\x80\xec\x5f'
    b'\x60\x51\x7f\xa9\x19\xb5\x4a\x0d\x2d\xe5\x7a\x9f\x93\xc9\x9c\xef'
    b'\xa0\xe0\x3b\x4d\xae\x2a\xf5\xb0\xc8\xeb\xbb\x3c\x83\x53\x99\x61'
    b'\x17\x2b\x04\x7e\xba\x77\xd6\x26\xe1\x69\x14\x63\x55\x21\x0c\x7d'
)

if __name__ == '__main__':
    import sys

    def bytes_from_hex(hex_string: str) -> bytes:
        """convert a hex string to bytes"""
        return bytes(int(''.join(v), 16) for v in zip(*([iter(hex_string)]*2)))

    mode, text, key = sys.argv[1:]
    func = {'e': encrypt_block, 'd': decrypt_block}[mode]
    text = bytes_from_hex(text)
    key = bytes_from_hex(key)
    with open(sys.stdout.fileno(), 'wb', closefd=False) as out:
        out.write(func(text, key))
