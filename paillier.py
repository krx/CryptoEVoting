#!/usr/bin/env python2
"""
Simple Paillier encryption library
"""

from Crypto.Util.number import inverse, getStrongPrime, getRandomRange, GCD


class PublicKey:
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1  # Works because p, q are the same size

    def encrypt(self, ptxt):
        if not isinstance(ptxt, (int, long)):
            raise TypeError('Plaintext must be a number')

        r = random_range_coprime(2, self.n, self.n)
        ctxt = (pow(self.g, ptxt, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return EncryptedMessage(self, ctxt, r)

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return self.n == other.n and self.g == other.g
        return False

    def __ne__(self, other):
        return not (self == other)


class PrivateKey:
    def __init__(self, pub, p, q):
        self.pub = pub
        self.lm = (p - 1) * (q - 1)
        self.mu = inverse(self.lm, pub.n)

    def decrypt(self, c):
        if isinstance(c, EncryptedMessage):
            if c.pub != self.pub:
                raise ValueError("Public keys don't match")
            c = c.ctxt

        if not isinstance(c, (int, long)):
            raise TypeError('Ciphertext must be a number')

        return (((pow(c, self.lm, self.pub.n_sq) - 1) / self.pub.n) * self.mu) % self.pub.n


class EncryptedMessage:
    def __init__(self, pub, ctxt, r=None):
        self.pub = pub
        self.ctxt = ctxt
        self.rand_num = r

    def __add__(self, other):
        add_val = 1
        if isinstance(other, EncryptedMessage):
            if self.pub != other.pub:
                raise ValueError("Public keys don't match")
            # To add two ctxts we just multiply them together
            add_val = other.ctxt
        elif isinstance(other, (int, long)):
            # To add an int k, we multiply by g^k
            add_val = pow(self.pub.g, other % self.pub.n_sq, self.pub.n_sq)

        return EncryptedMessage(self.pub, (self.ctxt * add_val) % self.pub.n_sq)

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        return self + -other

    def __mul__(self, other):
        if not isinstance(other, (int, long)):
            raise TypeError('Encrypted message must be multiplied by a number')

        return EncryptedMessage(self.pub, pow(self.ctxt, other % self.pub.n_sq, self.pub.n_sq))

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        return self * -1


def gen_keypair(nbits=2048):
    """ Generates a public/private key pair for Paillier encryption

    Args:
        nbits (int): Desired bit length of the modulus

    Returns:
        pub (PublicKey): Public key used for encryption
        priv (PrivateKey): Private key associated with the public key, used for decryption
    """
    p = getStrongPrime(nbits / 2)
    q = getStrongPrime(nbits / 2)
    pub = PublicKey(p * q)
    return pub, PrivateKey(pub, p, q)


def random_range_coprime(a, b, n):
    res = getRandomRange(a, b)
    while GCD(res, n) != 1:
        res = getRandomRange(a, b)
    return res
