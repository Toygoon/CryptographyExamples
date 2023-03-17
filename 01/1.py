import string
import random


def make_dict():
    keys = list(string.ascii_lowercase)
    vals = keys.copy()

    random.shuffle(vals)
    return {keys[i]: vals[i] for i in range(len(keys))}, \
        {vals[i]: keys[i] for i in range(len(keys))}


def convert(plain: str, X: dict):
    return ''.join([X.get(plain[i], ' ') for i in range(len(plain))])


if __name__ == '__main__':
    E, D = make_dict()

    plain = input('평문 입력 : ').lower()
    encrypted = convert(plain, E)
    decrypted = convert(encrypted, D)

    print(f'암호문 : {encrypted}')
    print(f'복호문 : {decrypted}')
