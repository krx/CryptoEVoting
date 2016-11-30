#!/usr/bin/env python2
"""
Simple Paillier encryption library
"""

from Crypto.Util.number import inverse, getStrongPrime, getRandomRange


class PublicKey:
    def __init__(self, n):
        self.n = n
        self.n_squared = n * n
        self.g = n + 1

    def encrypt(self, ptxt):
        if not isinstance(ptxt, (int, long)):
            raise TypeError('Plaintext must be a number')

        r = getRandomRange(2, self.n)
        ctxt = (pow(self.g, ptxt, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
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

        return (((pow(c, self.lm, self.pub.n_squared) - 1) / self.pub.n) * self.mu) % self.pub.n


class EncryptedMessage:
    def __init__(self, pub, ctxt, r=None):
        self.pub = pub
        self.ctxt = ctxt
        self.rand_num = r

    def __add__(self, other):
        res = None
        if isinstance(other, EncryptedMessage):
            if self.pub != other.pub:
                raise ValueError("Public keys don't match")
            res = (self.ctxt * other.ctxt) % self.pub.n_squared
        elif isinstance(other, int):
            res = (self.ctxt * pow(self.pub.g, other, self.pub.n_squared)) % self.pub.n_squared
        return EncryptedMessage(self.pub, res)

    def __sub__(self, other):
        res = None
        if isinstance(other, EncryptedMessage):
            if self.pub != other.pub:
                raise ValueError("Public keys don't match")
            res = self.ctxt + inverse(other.ctxt, self.pub.n_squared)
        elif isinstance(other, int):
            res = self.ctxt + inverse(other, self.pub.n_squared)
        return res

    def __mul__(self, other):
        res = None
        if isinstance(other, EncryptedMessage):
            if self.pub != other.pub:
                raise ValueError("Public keys don't match")
            res = pow(self.ctxt, other.ctxt, self.pub.n_squared)
        elif isinstance(other, int):
            res = pow(self.ctxt, other, self.pub.n_squared)
        return EncryptedMessage(self.pub, res)


def gen_keypair(nbits=2048):
    p = getStrongPrime(nbits / 2)
    q = getStrongPrime(nbits / 2)
    pub = PublicKey(p * q)
    return pub, PrivateKey(pub, p, q)
