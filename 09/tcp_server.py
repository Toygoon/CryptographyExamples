#!/usr/bin/env python3

import socket

host = 'localhost'
port = 12345

parent = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
parent.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

parent.bind((host, port))

# 3-Way handshaking을 대기
parent.listen(10)

# accept를 thread로 만들면 다수의 사용자에게 요청을 전달할 수 있음
print('Listen...')
child, address = parent.accept()
print(f'Accepted...')
# recvfrom 대신 recv를 사용할 수 있음
data = child.recv(65535)

print(f'Received {len(data)} bytes from {address}')

child.close()
parent.close()
