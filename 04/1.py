import hashlib
import base58check
from Crypto.Hash import RIPEMD160

# Alice는 타원 곡선 Ep(a, b)를 선택한다. 여기서 p는 소수이다.
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Alice는 곡선 상의 한 점 e1(…, …) 를 선택한다. <- generator
e1 = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# Alice는 계산에 사용할 다른 소수 q를 선택한다.
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


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
        tmp = ((3 * a[0] * a[0]) * extended_euclidian(p, 2 * b[1])) % p
    else:
        # a의 경우, P와 Q를 지나는 직선의 방정식
        tmp = ((b[1] - a[1]) * extended_euclidian(p, b[0] - a[0])) % p

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
        result = add(result, result)

        if binary[i] == '1':
            # Double(2배 연산)을 적용한 후 Add(G를 더함)
            result = add(result, g)

    return result


def generate_public_key(d: int):
    """
    개인키를 통해 공개키를 생성

    Args:
        d (int): 개인키

    Returns:
        tuple: e1을 key 만큼 곱한 공개키
    """

    return double_and_add(d, e1)


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
    r = RIPEMD160.new()
    r.update(bytes.fromhex(hash))

    # 4. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    hash = f'00{r.hexdigest()}'
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


if __name__ == '__main__':
    # 0. Having a private ECDSA key
    private_key = int(input('개인키 입력? '), 16)

    # 압축 공개키를 이용하여 Public Key Hash를 생성한 후, Base58Check 인코딩 방식의 주소를 출력한다.
    hash, addr = generate_addr(private_key)
    print(f'공개키 hash = {hash}')
    print(f'비트코인 주소 = {addr}')
