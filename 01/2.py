

def vigenere(plain: str, key: list, is_encrypt: bool = True):
    result = list()

    for i in range(len(plain)):
        p = ord(plain[i]) - 65
        k = key[i % len(key)]

        if is_encrypt:
            p += k
        else:
            p -= k

        result.append(chr(p % 26 + 65))

    return ''.join(result)


def autokey_cipher(plain: str, key: int, is_encrypt: bool = True):
    result = list()
    last_key = key

    for i in range(len(plain)):
        p = ord(plain[i]) - 65
        c = None

        if is_encrypt:
            c = p + last_key
            last_key = p
        else:
            c = p - last_key
            last_key = c

        result.append(chr(c % 26 + 65))

    return ''.join(result)


if __name__ == '__main__':
    plain = input('* 평문 입력 : ').replace(' ', '').upper()
    print()

    vig_key = [
        ord(x) - 65 for x in input('* Vigenere 암호? ').replace(' ', '').upper()]
    encrypted = vigenere(plain, vig_key)
    decrypted = vigenere(encrypted, vig_key, False)
    print(f'** 암호문 : {encrypted}')
    print(f'** 평문 : {decrypted}')
    print()

    auto_key = int(input('* 자동 키 암호? '))
    encrypted = autokey_cipher(plain, auto_key)
    decrypted = autokey_cipher(encrypted, auto_key, False)
    print(f'** 암호문 : {encrypted}')
    print(f'** 평문 : {decrypted}')
    print()
