#!/usr/bin/env python3

import socket

# Server에 대한 정보가 필요함
host = 'localhost'
port = 12345

# Socket 생성
# args: family, type, protocol
# (Family) AF_INET : IPv4
# (Type) DGRAM : UDP, Server와 Client 사이의 데이터 전송 방식
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

# 점유를 항상 하지 않도록 설정
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# bind는 tuple로
sock.bind((host, port))

# args : UDP가 가지고 있는 buffer의 크기
data, address = sock.recvfrom(65565)
print(f'received {len(data)} bytes from {address}')
print(f'data: {data}')

sock.close()
