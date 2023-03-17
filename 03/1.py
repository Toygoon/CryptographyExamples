import os
import random
import time
import hashlib
import secrets

# Alice는 타원 곡선 Ep(a, b)를 선택한다. 여기서 p는 소수이다.
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Alice는 곡선 상의 한 점 e1(…, …) 를 선택한다. <- generator
e1 = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# Alice는 계산에 사용할 다른 소수 q를 선택한다.
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def h(M: str):
    """
    SHA256을 이용하여 메시지를 암호화

    Args:
        M (str): 메시지

    Returns:
        int: 암호화된 메시지
    """

    return int(hashlib.sha256(M.encode()).hexdigest(), 16)


class ec:
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
            tmp = ((3 * a[0] * a[0]) * ec.extended_euclidian(p, 2 * b[1])) % p
        else:
            # a의 경우, P와 Q를 지나는 직선의 방정식
            tmp = ((b[1] - a[1]) * ec.extended_euclidian(p, b[0] - a[0])) % p

        x = (tmp ** 2 - a[0] - b[0]) % p
        y = (tmp * (a[0] - x) - a[1]) % p

        return x, y

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
            result = ec.add(result, result)

            if binary[i] == '1':
                # Double(2배 연산)을 적용한 후 Add(G를 더함)
                result = ec.add(result, g)

        return result

    def generate_public_key(d: int):
        """
        개인키를 통해 공개키를 생성

        Args:
            d (int): 개인키

        Returns:
            tuple: e1을 key 만큼 곱한 공개키
        """

        return ec.double_and_add(d, e1)

    def generate_private_key():
        """
        256비트의 난수를 생성하고, 이를 개인키로 이용하기 위한 함수

        Returns:
            int: 256비트 난수 개인키
        """

        while True:
            # 개인키의 randomness를 강화하기 위하여 os.urandom()과 random.random(), 그리고 time.time()을 모두 적용한 문자열을 생성
            text = f'{os.urandom(16).hex()}{random.random()}{time.time()}'
            # hashlib.sha256() 함수를 이용하여 256비트의 난수를 생성
            key = int(hashlib.sha256(text.encode()).hexdigest(), 16)

            # SECP256K1 곡선의 q보다 작으면 개인키로 사용하고, 아니면 또 다른 난수를 다시 생성
            if q > key:
                return key


def sign(M: str, d: int):
    """
    전자서명 함수

    Args:
        M (str): 서명하고자 하는 메시지
        d (int): 개인키

    Returns:
        tuple: 개인키를 통해 메시지를 서명한 전자서명 S1, S2
    """

    # Alice는 타원 곡선 E_p(a, b)를 선택한다. 여기서 p는 소수이다.
    # Y^2 mod p = (x^3 + ax + b) mod p
    a, b = [random.randint(1, 100) for _ in range(2)]

    # Alice는 임의의 수 r을 선택한다. 1 < r < q – 1
    r = secrets.randbelow(q - 1) + 1

    # 곡선 상의 한점 P(u, v) = r × e1 (…, …)을 계산한 후,
    u, _ = ec.double_and_add(r, e1)
    # S_1 = u mod q를 기억
    S1 = u % q

    # S_2 = (h(M) + d × S_1) × r^−1 mod q 를 계산
    S2 = (h(M) + d * S1) * ec.extended_euclidian(q, r) % q

    # (S1, S2)가 메시지 M의 서명
    return S1, S2


def verify(M, S1, S2, e2):
    """
    전자서명이 일치하는지 확인하는 함수

    Args:
        M (str): 검증하고자 하는 메시지
        S1 (int): sign()을 통해 생성된 전자서명 S1
        S2 (int): sign()을 통해 생성된 전자서명 S2
        e2 (tuple): 공개키

    Returns:
        bool: 메시지의 내용과 전자서명이 일치하는지에 대한 여부
    """

    # Bob은 M, S1, S2를 이용하여 두 개의 중간 결과 A와 B를 계산

    # tmp = S_2^−1 mod q
    tmp = ec.extended_euclidian(q, S2) % q
    # A = h(M) × S_2^−1 mod q
    A = h(M) * tmp
    # B = S_1 × S_2^-1 mod q
    B = S1 * tmp

    # T(x, y) = A × e1 (…, …) + B × e2 (…, …)
    x, _ = ec.add(ec.double_and_add(A, e1), ec.double_and_add(B, e2))

    # 프로그램의 검증을 위해 A와 B의 내용을 출력한다.
    print(f'\tA = {hex(A)}')
    print(f'\tB = {hex(B)}')

    # x mod q == S1 mod q일 경우, 검증 완료
    return x % q == S1 % q


if __name__ == '__main__':
    # Alice는 개인 키로 정수 d를 선택한다.
    d = ec.generate_private_key()
    # Alice는 곡선 상의 또 다른 한 점 e2(…, …) = d × e1(…, …)를 계산한다.
    e2 = ec.generate_public_key(d)

    M = input("메시지? ")
    S1, S2 = sign(M, d)
    print("1. Sign:")
    print("\tS1 =", hex(S1))
    print("\tS2 =", hex(S2))

    print("2. 정확한 서명을 입력할 경우:")
    if verify(M, S1, S2, e2):
        print("검증 성공")
    else:
        print("검증 실패")

    print("3. 잘못된 서명을 입력할 경우:")
    if verify(M, S1-1, S2-1, e2):
        print("검증 성공")
    else:
        print("검증 실패")
