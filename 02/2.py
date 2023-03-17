import os
import random
import time
import hashlib

# SECP256K1 타원 곡선의 P
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# SECP256K 타원 곡선 상의 고정된 점 G
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def extended_euclidian(n: tuple, b: tuple):
    """
    Extended Euclidian 알고리즘
    e의 역원인 d를 구하기 위해 사용함

    Args:
        n (tuple): gcd(n, b)에서의 n
        b (tuple): gcd(n, b)에서의 b

    Returns:
        tuple: key의 곱셈에 대한 역원
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


def add(p: tuple, q: tuple):
    """
    타원 곡선 상의 덧셈 연산

    Args:
        p (tuple): 타원 곡선 상의 두 점 중 P
        q (tuple): 타원 곡선 상의 두 점 중 Q

    Returns:
        tuple: 타원 곡선 상의 덧셈 결과
    """

    tmp = None

    if p == q:
        # b의 경우: λ = (3x1^2 + a)/(2y1)
        tmp = ((3 * p[0] * p[0]) * extended_euclidian(P, 2 * q[1])) % P
    else:
        # a의 경우, P와 Q를 지나는 직선의 방정식
        tmp = ((q[1] - p[1]) * extended_euclidian(P, q[0] - p[0])) % P

    x = (tmp ** 2 - p[0] - q[0]) % P
    y = (tmp * (p[0] - x) - p[1]) % P

    return x, y


def generate_key():
    """
    256비트의 개인키를 random으로 생성

    Returns:
        text, key: 생성된 평문과 key
    """

    while True:
        # 개인키의 randomness를 강화하기 위하여 os.urandom()과 random.random(), 그리고 time.time()을 모두 적용한 문자열을 생성
        text = f'{os.urandom(16).hex()}{random.random()}{time.time()}'
        # hashlib.sha256() 함수를 이용하여 256비트의 난수를 생성
        key = int(hashlib.sha256(text.encode()).hexdigest(), 16)

        # SECP256K1 곡선의 p보다 작으면 개인키로 사용하고, 아니면 또 다른 난수를 다시 생성
        if P > key:
            return text, key


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


if __name__ == '__main__':
    # 개인키 생성
    text, private_key = generate_key()
    private_key = 0x771ab89947b6e39e1aaa7610085e5657e1eef2da7ccdf7af7d35b0413e661d38
    # 공개키 계산
    public_key = double_and_add(private_key, G)

    # 출력
    print(f'개인키(16진수) = {hex(private_key)}')
    print(f'개인키(10진수) = {private_key}')
    print()

    print(f'공개키(16진수) = ({hex(public_key[0])},')
    print(f'\t\t {hex(public_key[1])})')
    print(f'공개키(10진수) = ({public_key[0]},')
    print(f'\t\t {public_key[1]})')
