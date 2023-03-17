from cryptography.fernet import Fernet

if __name__ == '__main__':
    fr = Fernet(Fernet.generate_key())

    f = open('data.txt', 'r', encoding='UTF-8')
    plain = f.read()
    f.close()

    f = open('encrypted.txt', 'w', encoding='UTF-8')
    encrypted = fr.encrypt(plain.encode())
    f.write(encrypted.decode())
    f.close()

    f = open('encrypted.txt', 'r', encoding='UTF-8')
    decrypted = fr.decrypt(f.read().encode()).decode()

    print('** 복호화 결과 **')
    print(decrypted)
