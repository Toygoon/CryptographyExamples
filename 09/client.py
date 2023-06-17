#!/usr/bin/env python3

import socket

# 접속하고자 하는 Server의 정보
server_host = "localhost"
server_port = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

msg = b"This is the message"
# 전송
sock.sendto(msg, (server_host, server_port))

sock.close()
