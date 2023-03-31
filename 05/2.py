import time
import struct
import hashlib


def pow(msg, bits):
    bits = bytes.fromhex(bits)
    target = int.from_bytes(bits[1:], byteorder='big') << 8 * (bits[0] - 3)

    nonce = 0
    ext_nonce = int(time.time())

    print(f"Target: 0x{format(target, 'x').zfill(64)}")

    start = time.time()
    while True:
        data = msg.encode('utf-8') + struct.pack('<I',
                                                 ext_nonce) + struct.pack('<I', nonce)
        result = hashlib.sha256(hashlib.sha256(
            data).digest()).digest()

        if int.from_bytes(result, byteorder='big') <= target:
            break

        nonce += 1

        if nonce >= 2**32:
            ext_nonce += 1
            nonce = 0

    end = time.time()

    print(f'메시지: {msg}, Extra nonce: {ext_nonce}, nonce: {nonce}')
    print(f'실행 시간: {end - start}초')
    print(f'Hash result: 0x{result.hex()}')


if __name__ == '__main__':
    msg = input('메시지의 내용? ')
    bits = input('Target bits? ')

    pow(msg, bits)
