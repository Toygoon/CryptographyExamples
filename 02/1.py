from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# 알고리즘이 사용하는 비트
HASH_PADDING = 256


def is_long_text(plain_text: str, key_size: int):
    """
    plain_text가 key_size를 통해 HASH_PADDING을 사용하여
    암호화할 수 있는 최대 메시지의 크기가 초과하는지를 확인해주는 함수

    Args:
        plain_text (str): 암호화하고자 하는 plain text
        key_size (int): 해시 알고리즘이 사용하는 비트

    Returns:
        bool: 메시지의 크기가 최대 크기를 초과하는지에 대한 여부
    """

    return len(plain_text.encode()) > (key_size / 8 - 2 * HASH_PADDING / 8 - 2)


def read_keys():
    """
    같은 디렉토리에 있는 공개 키인 'public_key.pem' 파일과
    개인 키인 'private_key.pem' 파일을 읽어 각 키에 적합한 객체로 반환하는 함수

    Returns:
        PUBLIC_KEY_TYPES, PRIVATE_KEY_TYPES : 각 키 파일을 읽은 값
    """

    # public_key.pem 읽기
    with open('public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend())

    # private_key.pem 읽기
    with open('private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend())

    return public_key, private_key


def convert_to_bytes(text):
    """
    text가 str인 경우 bytes로 변환해주는 함수

    Args:
        text (str, bytes): text

    Returns:
        bytes: bytes 형식의 text
    """
    if type(text) is str:
        return text.encode()

    return text


def convert_aes(text, aes_key: bytes, is_encrypt: bool = True):
    """
    AES 알고리즘을 이용하여 plain text를 암호화, 혹은 encrypted text를 복호화한 후 반환해주는 함수

    Args:
        text: plain text 혹은 encrypted text
        aes_key (bytes): AES 암호화에 사용될 key
        is_encrypt (bool, optional): True이면 암호화, False이면 복호화

    Returns:
        bytes: 암호화, 복호화 결과 값
    """

    # Fernet 객체 생성
    f = Fernet(aes_key)

    # bytes 형식으로 사용
    text = convert_to_bytes(text)

    # 암호화
    if is_encrypt:
        return f.encrypt(text)

    # 복호화
    return f.decrypt(text)


def convert_rsa(text, key, is_encrypt: bool = True):
    """
    RSA 알고리즘을 이용하여 plain text를 암호화, 혹은 encrypted text를 복호화한 후 반환해주는 함수

    Args:
        text: plain text 혹은 encrypted text
        key (PUBLIC_KEY_TYPES, PRIVATE_KEY_TYPES): public_key 혹은 private_key
        is_encrypt (bool, optional): _description_. Defaults to True.

    Returns:
        _type_: _description_
    """

    # OAEP 객체 생성
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None)

    # bytes 형식으로 사용
    text = convert_to_bytes(text)

    # 암호화
    if is_encrypt:
        return key.encrypt(text, oaep)

    # 복호화
    return key.decrypt(text, oaep)


if __name__ == '__main__':
    # 평문 입력
    # plain_text = input('평문 입력 : ')
    plain_text = 'hello'

    # key 가져오기
    public_key, private_key = read_keys()
    aes_key = Fernet.generate_key()

    enc_msg = None
    is_long_text = is_long_text(plain_text, public_key.key_size)

    if is_long_text:
        # 가. 길이가 긴 메시지는 AES를 이용하여 암호화한다.
        enc_msg = convert_aes(plain_text, aes_key)
        # 나. 공개키를 이용하여 AES의 키(aes_key)를 암호화한다.
        enc_key = convert_rsa(aes_key, public_key)
    else:
        enc_msg = convert_rsa(plain_text, public_key)

    aes_key = None
    decrypted_text = None

    # 다. enc_msg와 enc_key를 insecure channel로 수신자에게 전달한다.
    if is_long_text:
        # 라. 수신자는 개인키를 이용하여 enc_key를 복호화한다.
        aes_key = convert_rsa(enc_key, private_key, False)
        # 마. aes_key를 이용하여 enc_msg를 복호화하여 평문을 복원한다.
        decrypted_text = convert_aes(enc_msg, aes_key, False)
    else:
        decrypted_text = convert_rsa(enc_msg, private_key, False)

    print(plain_text == decrypted_text.decode())
