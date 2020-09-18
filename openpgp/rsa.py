"""RSA PKCS #1"""
import math
import random
import secrets
import itertools


def find_prime(bitsize, secbits=256):
    rounds = secbits // 2
    while True:
        pot_prime = secrets.randbits(bitsize)
        if not pot_prime & 1:
            continue
        if miller_rabin(pot_prime, rounds):
            return pot_prime


def miller_rabin(n, k):
    rnd = random.SystemRandom()
    r = n - 1
    s = 0
    while not r & 1:  # == not r % 2 (speed + ~25%)
        r >>= 1  # == r // 2  (speed + ~17%)
        s += 1
    for __ in range(k):
        a = rnd.randint(2, n-2)
        x = pow(a, r, n)
        if x in (1, n-1):
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n-1:
                break
        else:
            return False
    return True


def generate_key(mod_bits):
    prime_bits = mod_bits // 2
    p, q = find_prime(prime_bits+5), find_prime(prime_bits-5)
    n = p*q
    e = 65537

    phi_n = n - p - q + 1
    assert e < phi_n
    gcd, d, __ = extended_euclid(e, phi_n)
    assert gcd == 1
    d %= phi_n
    assert d*e % phi_n == 1

    return (d, n), (e, n)


def basic_crypt(key, text):
    assert 0 <= text < key[1] - 1
    return pow(text, *key)


def crypt_bytes(key, text):
    return (basic_crypt(key, int.from_bytes(text, 'big'))
            .to_bytes(math.ceil(key[1].bit_length() / 8), 'big'))


def rsaes_pkcs1_v1_5_encrypt(key, message):
    mod_length = math.ceil(math.log2(key[1]) / 8)
    encoded = eme_pkcs1_v1_5_encode(message, mod_length)
    return crypt_bytes(key, encoded)


def rsaes_pkcs1_v1_5_decrypt(key, message):
    decrypted = crypt_bytes(key, message)
    return eme_pkcs1_v1_5_decode(decrypted)


def eme_pkcs1_v1_5_encode(message, mod_length):
    infinite_bytes = (f() for f in itertools.cycle([lambda: secrets.randbelow(256)]))
    random_nonzero, __ = zip(*zip(filter(int, infinite_bytes), range(mod_length - len(message) - 3)))
    return b''.join((b'\x00\x02', bytes(random_nonzero), b'\x00', message))


def eme_pkcs1_v1_5_decode(message):
    return bytes(itertools.dropwhile(int, message[2:]))[1:]


def emsa_pkcs1_v1_5(message_hash, out_length):
    return b''.join((
        b'\x00\x01',
        bytes([0xff]*(out_length-len(message_hash)-3)),
        b'\x00',
        message_hash,
    ))


def rsassa_pkcs1_v1_5_sign(message_hash, key):
    encoded = emsa_pkcs1_v1_5(message_hash, math.ceil(key[1].bit_length() / 8))
    return crypt_bytes(key, encoded)


def rsassa_pkcs1_v1_5_verify(message_hash, signature, key):
    encoded = emsa_pkcs1_v1_5(message_hash, math.ceil(key[1].bit_length() / 8))
    return encoded == crypt_bytes(key, signature)


def extended_euclid(a, b):
    """implement the extended Euclidean algorithm"""
    r_old = a
    s_old = 1
    t_old = 0
    r_new = b
    s_new = 0
    t_new = 1
    while r_new:
        r_old, (q, r_new) = r_new, divmod(r_old, r_new)
        s_old, s_new = s_new, s_old - q*s_new
        t_old, t_new = t_new, t_old - q*t_new
    return r_old, s_old, t_old
