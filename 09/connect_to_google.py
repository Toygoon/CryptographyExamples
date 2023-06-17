#!/usr/bin/env python3

import socket

server_host = 'google.com'
server_port = 80

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.connect((server_host, server_port))

print(sock)
print(f'Socket connect to {server_host}')

msg = b'GET / HTTP/1.1\r\n\r\n'
sock.sendall(msg)
data = sock.recv(65535)

print(f'From Google {server_host}')
print(data)

sock.close()
