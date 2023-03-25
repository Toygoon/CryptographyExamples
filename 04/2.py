#!/usr/bin/env python
# coding: utf-8

# In[456]:


import struct
import sys
import hashlib
import base58check
import os
from Crypto.Hash import RIPEMD160


# In[457]:


# Alice는 타원 곡선 Ep(a, b)를 선택한다. 여기서 p는 소수이다.
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Alice는 곡선 상의 한 점 e1(…, …) 를 선택한다. <- generator
e1 = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# Alice는 계산에 사용할 다른 소수 q를 선택한다.
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# In[458]:


"""
Implementing SHA-256 from scratch was fun, but for RIPEMD160 I am
taking an existing implementation and made some cleanups and api changes.
"""

# ripemd.py - pure Python implementation of the RIPEMD-160 algorithm.
# Bjorn Edstrom <be@bjrn.se> 16 december 2007.
##
# Copyrights
# ==========
##
# This code is a derived from an implementation by Markus Friedl which is
# subject to the following license. This Python implementation is not
# subject to any other license.
##
# /*
# * Copyright (c) 2001 Markus Friedl.  All rights reserved.
# *
# * Redistribution and use in source and binary forms, with or without
# * modification, are permitted provided that the following conditions
# * are met:
# * 1. Redistributions of source code must retain the above copyright
# *    notice, this list of conditions and the following disclaimer.
# * 2. Redistributions in binary form must reproduce the above copyright
# *    notice, this list of conditions and the following disclaimer in the
# *    documentation and/or other materials provided with the distribution.
# *
# * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES LOSS OF USE,
# * DATA, OR PROFITS OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# */
# /*
## * Preneel, Bosselaers, Dobbertin, "The Cryptographic Hash Function RIPEMD-160",
# * RSA Laboratories, CryptoBytes, Volume 3, Number 2, Autumn 1997,
# * ftp://ftp.rsasecurity.com/pub/cryptobytes/crypto3n2.pdf
# */


# -----------------------------------------------------------------------------
# public interface


def ripemd160(b: bytes) -> bytes:
    """ simple wrapper for a simpler API to this hash function, just bytes to bytes """
    ctx = RMDContext()
    # print(ctx.state, ctx.count, ctx.buffer)
    RMD160Update(ctx, b, len(b))
    # print(ctx.state, ctx.count, ctx.buffer)
    digest = RMD160Final(ctx)
    # print(ctx.state, ctx.count, ctx.buffer)
    print(ctx.state)
    print(digest)
    return digest

# -----------------------------------------------------------------------------


class RMDContext:
    def __init__(self):
        self.state = [0x67452301, 0xEFCDAB89,
                      0x98BADCFE, 0x10325476, 0xC3D2E1F0]  # uint32
        self.count = 0  # uint64
        self.buffer = [0]*64  # uchar


def RMD160Update(ctx, inp, inplen):
    have = int((ctx.count // 8) % 64)
    inplen = int(inplen)
    need = 64 - have
    ctx.count += 8 * inplen
    off = 0
    if inplen >= need:
        if have:
            for i in range(need):
                ctx.buffer[have+i] = inp[i]
            RMD160Transform(ctx.state, ctx.buffer)
            off = need
            have = 0
        while off + 64 <= inplen:
            RMD160Transform(ctx.state, inp[off:])  # <---
            off += 64
    if off < inplen:
        for i in range(inplen - off):
            ctx.buffer[have+i] = inp[off+i]


def RMD160Final(ctx):
    size = struct.pack("<Q", ctx.count)
    padlen = 64 - ((ctx.count // 8) % 64)
    if padlen < 1 + 8:
        padlen += 64
    RMD160Update(ctx, PADDING, padlen-8)
    RMD160Update(ctx, size, 8)
    print('*ctx.state', *ctx.state)
    return struct.pack("<5L", *ctx.state)

# -----------------------------------------------------------------------------


K0 = 0x00000000
K1 = 0x5A827999
K2 = 0x6ED9EBA1
K3 = 0x8F1BBCDC
K4 = 0xA953FD4E
KK0 = 0x50A28BE6
KK1 = 0x5C4DD124
KK2 = 0x6D703EF3
KK3 = 0x7A6D76E9
KK4 = 0x00000000

PADDING = [0x80] + [0]*63


def ROL(n, x):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))


def F0(x, y, z):
    return x ^ y ^ z


def F1(x, y, z):
    return (x & y) | (((~x) % 0x100000000) & z)


def F2(x, y, z):
    return (x | ((~y) % 0x100000000)) ^ z


def F3(x, y, z):
    return (x & z) | (((~z) % 0x100000000) & y)


def F4(x, y, z):
    return x ^ (y | ((~z) % 0x100000000))


def R(a, b, c, d, e, Fj, Kj, sj, rj, X):
    a = ROL(sj, (a + Fj(b, c, d) + X[rj] + Kj) % 0x100000000) + e
    c = ROL(10, c)
    return a % 0x100000000, c


def RMD160Transform(state, block):  # uint32 state[5], uchar block[64]
    x = [0]*16
    assert sys.byteorder == 'little', "Only little endian is supported atm for RIPEMD160"
    x = struct.unpack('<16L', bytes(block[0:64]))

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    # /* Round 1 */
    a, c = R(a, b, c, d, e, F0, K0, 11,  0, x)
    e, b = R(e, a, b, c, d, F0, K0, 14,  1, x)
    d, a = R(d, e, a, b, c, F0, K0, 15,  2, x)
    c, e = R(c, d, e, a, b, F0, K0, 12,  3, x)
    b, d = R(b, c, d, e, a, F0, K0,  5,  4, x)
    a, c = R(a, b, c, d, e, F0, K0,  8,  5, x)
    e, b = R(e, a, b, c, d, F0, K0,  7,  6, x)
    d, a = R(d, e, a, b, c, F0, K0,  9,  7, x)
    c, e = R(c, d, e, a, b, F0, K0, 11,  8, x)
    b, d = R(b, c, d, e, a, F0, K0, 13,  9, x)
    a, c = R(a, b, c, d, e, F0, K0, 14, 10, x)
    e, b = R(e, a, b, c, d, F0, K0, 15, 11, x)
    d, a = R(d, e, a, b, c, F0, K0,  6, 12, x)
    c, e = R(c, d, e, a, b, F0, K0,  7, 13, x)
    b, d = R(b, c, d, e, a, F0, K0,  9, 14, x)
    a, c = R(a, b, c, d, e, F0, K0,  8, 15, x)  # /* #15 */
    # /* Round 2 */
    e, b = R(e, a, b, c, d, F1, K1,  7,  7, x)
    d, a = R(d, e, a, b, c, F1, K1,  6,  4, x)
    c, e = R(c, d, e, a, b, F1, K1,  8, 13, x)
    b, d = R(b, c, d, e, a, F1, K1, 13,  1, x)
    a, c = R(a, b, c, d, e, F1, K1, 11, 10, x)
    e, b = R(e, a, b, c, d, F1, K1,  9,  6, x)
    d, a = R(d, e, a, b, c, F1, K1,  7, 15, x)
    c, e = R(c, d, e, a, b, F1, K1, 15,  3, x)
    b, d = R(b, c, d, e, a, F1, K1,  7, 12, x)
    a, c = R(a, b, c, d, e, F1, K1, 12,  0, x)
    e, b = R(e, a, b, c, d, F1, K1, 15,  9, x)
    d, a = R(d, e, a, b, c, F1, K1,  9,  5, x)
    c, e = R(c, d, e, a, b, F1, K1, 11,  2, x)
    b, d = R(b, c, d, e, a, F1, K1,  7, 14, x)
    a, c = R(a, b, c, d, e, F1, K1, 13, 11, x)
    e, b = R(e, a, b, c, d, F1, K1, 12,  8, x)  # /* #31 */
    # /* Round 3 */
    d, a = R(d, e, a, b, c, F2, K2, 11,  3, x)
    c, e = R(c, d, e, a, b, F2, K2, 13, 10, x)
    b, d = R(b, c, d, e, a, F2, K2,  6, 14, x)
    a, c = R(a, b, c, d, e, F2, K2,  7,  4, x)
    e, b = R(e, a, b, c, d, F2, K2, 14,  9, x)
    d, a = R(d, e, a, b, c, F2, K2,  9, 15, x)
    c, e = R(c, d, e, a, b, F2, K2, 13,  8, x)
    b, d = R(b, c, d, e, a, F2, K2, 15,  1, x)
    a, c = R(a, b, c, d, e, F2, K2, 14,  2, x)
    e, b = R(e, a, b, c, d, F2, K2,  8,  7, x)
    d, a = R(d, e, a, b, c, F2, K2, 13,  0, x)
    c, e = R(c, d, e, a, b, F2, K2,  6,  6, x)
    b, d = R(b, c, d, e, a, F2, K2,  5, 13, x)
    a, c = R(a, b, c, d, e, F2, K2, 12, 11, x)
    e, b = R(e, a, b, c, d, F2, K2,  7,  5, x)
    d, a = R(d, e, a, b, c, F2, K2,  5, 12, x)  # /* #47 */
    # /* Round 4 */
    c, e = R(c, d, e, a, b, F3, K3, 11,  1, x)
    b, d = R(b, c, d, e, a, F3, K3, 12,  9, x)
    a, c = R(a, b, c, d, e, F3, K3, 14, 11, x)
    e, b = R(e, a, b, c, d, F3, K3, 15, 10, x)
    d, a = R(d, e, a, b, c, F3, K3, 14,  0, x)
    c, e = R(c, d, e, a, b, F3, K3, 15,  8, x)
    b, d = R(b, c, d, e, a, F3, K3,  9, 12, x)
    a, c = R(a, b, c, d, e, F3, K3,  8,  4, x)
    e, b = R(e, a, b, c, d, F3, K3,  9, 13, x)
    d, a = R(d, e, a, b, c, F3, K3, 14,  3, x)
    c, e = R(c, d, e, a, b, F3, K3,  5,  7, x)
    b, d = R(b, c, d, e, a, F3, K3,  6, 15, x)
    a, c = R(a, b, c, d, e, F3, K3,  8, 14, x)
    e, b = R(e, a, b, c, d, F3, K3,  6,  5, x)
    d, a = R(d, e, a, b, c, F3, K3,  5,  6, x)
    c, e = R(c, d, e, a, b, F3, K3, 12,  2, x)  # /* #63 */
    # /* Round 5 */
    b, d = R(b, c, d, e, a, F4, K4,  9,  4, x)
    a, c = R(a, b, c, d, e, F4, K4, 15,  0, x)
    e, b = R(e, a, b, c, d, F4, K4,  5,  5, x)
    d, a = R(d, e, a, b, c, F4, K4, 11,  9, x)
    c, e = R(c, d, e, a, b, F4, K4,  6,  7, x)
    b, d = R(b, c, d, e, a, F4, K4,  8, 12, x)
    a, c = R(a, b, c, d, e, F4, K4, 13,  2, x)
    e, b = R(e, a, b, c, d, F4, K4, 12, 10, x)
    d, a = R(d, e, a, b, c, F4, K4,  5, 14, x)
    c, e = R(c, d, e, a, b, F4, K4, 12,  1, x)
    b, d = R(b, c, d, e, a, F4, K4, 13,  3, x)
    a, c = R(a, b, c, d, e, F4, K4, 14,  8, x)
    e, b = R(e, a, b, c, d, F4, K4, 11, 11, x)
    d, a = R(d, e, a, b, c, F4, K4,  8,  6, x)
    c, e = R(c, d, e, a, b, F4, K4,  5, 15, x)
    b, d = R(b, c, d, e, a, F4, K4,  6, 13, x)  # /* #79 */

    aa = a
    bb = b
    cc = c
    dd = d
    ee = e

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    # /* Parallel round 1 */
    a, c = R(a, b, c, d, e, F4, KK0,  8,  5, x)
    e, b = R(e, a, b, c, d, F4, KK0,  9, 14, x)
    d, a = R(d, e, a, b, c, F4, KK0,  9,  7, x)
    c, e = R(c, d, e, a, b, F4, KK0, 11,  0, x)
    b, d = R(b, c, d, e, a, F4, KK0, 13,  9, x)
    a, c = R(a, b, c, d, e, F4, KK0, 15,  2, x)
    e, b = R(e, a, b, c, d, F4, KK0, 15, 11, x)
    d, a = R(d, e, a, b, c, F4, KK0,  5,  4, x)
    c, e = R(c, d, e, a, b, F4, KK0,  7, 13, x)
    b, d = R(b, c, d, e, a, F4, KK0,  7,  6, x)
    a, c = R(a, b, c, d, e, F4, KK0,  8, 15, x)
    e, b = R(e, a, b, c, d, F4, KK0, 11,  8, x)
    d, a = R(d, e, a, b, c, F4, KK0, 14,  1, x)
    c, e = R(c, d, e, a, b, F4, KK0, 14, 10, x)
    b, d = R(b, c, d, e, a, F4, KK0, 12,  3, x)
    a, c = R(a, b, c, d, e, F4, KK0,  6, 12, x)  # /* #15 */
    # /* Parallel round 2 */
    e, b = R(e, a, b, c, d, F3, KK1,  9,  6, x)
    d, a = R(d, e, a, b, c, F3, KK1, 13, 11, x)
    c, e = R(c, d, e, a, b, F3, KK1, 15,  3, x)
    b, d = R(b, c, d, e, a, F3, KK1,  7,  7, x)
    a, c = R(a, b, c, d, e, F3, KK1, 12,  0, x)
    e, b = R(e, a, b, c, d, F3, KK1,  8, 13, x)
    d, a = R(d, e, a, b, c, F3, KK1,  9,  5, x)
    c, e = R(c, d, e, a, b, F3, KK1, 11, 10, x)
    b, d = R(b, c, d, e, a, F3, KK1,  7, 14, x)
    a, c = R(a, b, c, d, e, F3, KK1,  7, 15, x)
    e, b = R(e, a, b, c, d, F3, KK1, 12,  8, x)
    d, a = R(d, e, a, b, c, F3, KK1,  7, 12, x)
    c, e = R(c, d, e, a, b, F3, KK1,  6,  4, x)
    b, d = R(b, c, d, e, a, F3, KK1, 15,  9, x)
    a, c = R(a, b, c, d, e, F3, KK1, 13,  1, x)
    e, b = R(e, a, b, c, d, F3, KK1, 11,  2, x)  # /* #31 */
    # /* Parallel round 3 */
    d, a = R(d, e, a, b, c, F2, KK2,  9, 15, x)
    c, e = R(c, d, e, a, b, F2, KK2,  7,  5, x)
    b, d = R(b, c, d, e, a, F2, KK2, 15,  1, x)
    a, c = R(a, b, c, d, e, F2, KK2, 11,  3, x)
    e, b = R(e, a, b, c, d, F2, KK2,  8,  7, x)
    d, a = R(d, e, a, b, c, F2, KK2,  6, 14, x)
    c, e = R(c, d, e, a, b, F2, KK2,  6,  6, x)
    b, d = R(b, c, d, e, a, F2, KK2, 14,  9, x)
    a, c = R(a, b, c, d, e, F2, KK2, 12, 11, x)
    e, b = R(e, a, b, c, d, F2, KK2, 13,  8, x)
    d, a = R(d, e, a, b, c, F2, KK2,  5, 12, x)
    c, e = R(c, d, e, a, b, F2, KK2, 14,  2, x)
    b, d = R(b, c, d, e, a, F2, KK2, 13, 10, x)
    a, c = R(a, b, c, d, e, F2, KK2, 13,  0, x)
    e, b = R(e, a, b, c, d, F2, KK2,  7,  4, x)
    d, a = R(d, e, a, b, c, F2, KK2,  5, 13, x)  # /* #47 */
    # /* Parallel round 4 */
    c, e = R(c, d, e, a, b, F1, KK3, 15,  8, x)
    b, d = R(b, c, d, e, a, F1, KK3,  5,  6, x)
    a, c = R(a, b, c, d, e, F1, KK3,  8,  4, x)
    e, b = R(e, a, b, c, d, F1, KK3, 11,  1, x)
    d, a = R(d, e, a, b, c, F1, KK3, 14,  3, x)
    c, e = R(c, d, e, a, b, F1, KK3, 14, 11, x)
    b, d = R(b, c, d, e, a, F1, KK3,  6, 15, x)
    a, c = R(a, b, c, d, e, F1, KK3, 14,  0, x)
    e, b = R(e, a, b, c, d, F1, KK3,  6,  5, x)
    d, a = R(d, e, a, b, c, F1, KK3,  9, 12, x)
    c, e = R(c, d, e, a, b, F1, KK3, 12,  2, x)
    b, d = R(b, c, d, e, a, F1, KK3,  9, 13, x)
    a, c = R(a, b, c, d, e, F1, KK3, 12,  9, x)
    e, b = R(e, a, b, c, d, F1, KK3,  5,  7, x)
    d, a = R(d, e, a, b, c, F1, KK3, 15, 10, x)
    c, e = R(c, d, e, a, b, F1, KK3,  8, 14, x)  # /* #63 */
    # /* Parallel round 5 */
    b, d = R(b, c, d, e, a, F0, KK4,  8, 12, x)
    a, c = R(a, b, c, d, e, F0, KK4,  5, 15, x)
    e, b = R(e, a, b, c, d, F0, KK4, 12, 10, x)
    d, a = R(d, e, a, b, c, F0, KK4,  9,  4, x)
    c, e = R(c, d, e, a, b, F0, KK4, 12,  1, x)
    b, d = R(b, c, d, e, a, F0, KK4,  5,  5, x)
    a, c = R(a, b, c, d, e, F0, KK4, 14,  8, x)
    e, b = R(e, a, b, c, d, F0, KK4,  6,  7, x)
    d, a = R(d, e, a, b, c, F0, KK4,  8,  6, x)
    c, e = R(c, d, e, a, b, F0, KK4, 13,  2, x)
    b, d = R(b, c, d, e, a, F0, KK4,  6, 13, x)
    a, c = R(a, b, c, d, e, F0, KK4,  5, 14, x)
    e, b = R(e, a, b, c, d, F0, KK4, 15,  0, x)
    d, a = R(d, e, a, b, c, F0, KK4, 13,  3, x)
    c, e = R(c, d, e, a, b, F0, KK4, 11,  9, x)
    b, d = R(b, c, d, e, a, F0, KK4, 11, 11, x)  # /* #79 */

    t = (state[1] + cc + d) % 0x100000000
    state[1] = (state[2] + dd + e) % 0x100000000
    state[2] = (state[3] + ee + a) % 0x100000000
    state[3] = (state[4] + aa + b) % 0x100000000
    state[4] = (state[0] + bb + c) % 0x100000000
    state[0] = t % 0x100000000


# In[459]:


def extended_euclidian(n, b):
    """
    Extended Euclidian 알고리즘
    곱셈에 대한 역원을 구하기 위해 사용함

    Args:
        n (Any): gcd(n, b)에서의 n
        b (Any): gcd(n, b)에서의 b

    Returns:
        Any: 곱셈에 대한 역원
    """

    # r1 <- n; r2 <- b; t1 <- 0; t2 <- 1;
    r1, r2, t1, t2 = n, b % n, 0, 1

    while r2 > 0:
        # q <- r1 / r2;
        q = r1 // r2

        # r <- r1 - q * r2;
        r = r1 - q * r2
        # r1 <- r2; r2 <- r;
        r1, r2 = r2, r
        # t <- t1 + q * t2;
        t = t1 - q * t2
        # t1 <- t2; t2 <- t;
        t1, t2 = t2, t

    return t1 % n


# In[460]:


def add(a: tuple, b: tuple):
    """
    타원 곡선 상의 덧셈 연산

    Args:
        p (tuple): 타원 곡선 상의 두 점 중 P
        q (tuple): 타원 곡선 상의 두 점 중 Q

    Returns:
        tuple: 타원 곡선 상의 덧셈 결과
    """

    tmp = None

    if a == b:
        # b의 경우: λ = (3x1^2 + a)/(2y1)
        tmp = ((3 * a[0] * a[0]) * extended_euclidian(p, 2 * b[1])) % p
    else:
        # a의 경우, P와 Q를 지나는 직선의 방정식
        tmp = ((b[1] - a[1]) * extended_euclidian(p, b[0] - a[0])) % p

    x = (tmp ** 2 - a[0] - b[0]) % p
    y = (tmp * (a[0] - x) - a[1]) % p

    return x, y


# In[461]:


def double_and_add(x: int, g: tuple):
    """
    Double-and-Add 알고리즘
    공개키를 만들기 위해 G를 x번 더하는 연산이 필요
    개인키가 x라고 하면 공개 키는 x * G의 결과로 생성됨

    Args:
        x (int): 개인키 (256 bit)
        g (tuple): 타원 곡선 상의 고정된 점 (공개)

    Returns:
        tuple: x * g의 결과 값
    """

    binary = bin(x)[3:]
    result = g[0], g[1]

    # left-to-right로 k의 비트를 조사
    for i in range(len(binary)):
        # Double만 적용
        result = add(result, result)

        if binary[i] == '1':
            # Double(2배 연산)을 적용한 후 Add(G를 더함)
            result = add(result, g)

    return result


# In[462]:


def generate_public_key(d: int):
    """
    개인키를 통해 공개키를 생성

    Args:
        d (int): 개인키

    Returns:
        tuple: e1을 key 만큼 곱한 공개키
    """

    return double_and_add(d, e1)


# In[463]:


def generate_addr(private_key: int):
    """
    압축 공개키를 이용하여 Public Key Hash를 생성하고, 
    이를 이용하여 비트코인 주소를 출력

    Args:
        private_key (int): 개인키

    Returns:
        hash, address: 공개키의 Hash 값과, 비트코인 주소를 반환
    """

    # 1. Take the corresponding public key generated with it
    x, y = generate_public_key(private_key)

    # (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)
    hash = f'{"03" if y % 2 else "02"}{format(x, "x")}'

    # 2. Perform SHA-256 hashing on the public key
    hash = hashlib.sha256(bytes.fromhex(hash)).hexdigest()

    # 3. Perform RIPEMD-160 hashing on the result of SHA-256
    # r = RIPEMD160.new()
    # r.update(bytes.fromhex(hash))

    r = ripemd160(bytes.fromhex(hash))
    # 4. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    hash = f'00{bytes.hex(r)}'
    chk = hash

    # 5. Perform SHA-256 hash on the extended RIPEMD-160 result
    # 6. Perform SHA-256 hash on the result of the previous SHA-256 hash
    for _ in range(2):
        chk = hashlib.sha256(bytes.fromhex(chk)).hexdigest()

    # 7. Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
    # 8. Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
    addr = f'{hash}{chk[:8]}'

    # 9. Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
    return hash, base58check.b58encode(bytes.fromhex(addr)).decode()


# In[464]:


if __name__ == '__main__':
    # 0. Having a private ECDSA key
    # private_key = os.urandom(32).hex()
    # print(private_key)
    # private_key = int(private_key, 16)
    # print(private_key)
    private_key = 0x0
    # private_key = 0xddad6ba2ceef0bbb1404e7a9bc33ddab098885678be0a79a14e9a802844674f9
    # 압축 공개키를 이용하여 Public Key Hash를 생성한 후, Base58Check 인코딩 방식의 주소를 출력한다.
    hash, addr = generate_addr(private_key)
    print(f'공개키 hash = {hash}')
    print(f'비트코인 주소 = {addr}')
