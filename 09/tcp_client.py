#!/usr/bin/env python3

import socket

server_host = 'localhost'
server_port = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.connect((server_host, server_port))

msg = b'yu cse'
# sock.sendto(msg, (server_host, server_port))
# sendall은 UDP에서 사용할 수 없음
sock.sendall(msg)

sock.close()
