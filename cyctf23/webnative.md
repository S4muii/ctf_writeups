## Challenge Name: webnative


Category: RE / WebAssembly

Points: 490

Solves: 5

Attached Files:
* [webnative.zip](./files/webnative.zip)

I have to start by saying that this is my first web assembly chall ever and I'm very excited to share how I solved it with you guys , hope you like it.
I started by looking at the binary using `file` command utility the output was 
```bash
➜  webnative file webnative.wasm 
webnative.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
```

WebAssembly huh ? what even is that ? 
A quick google search yielded 
>WebAssembly defines a portable binary-code format and a corresponding text format for executable programs as well as software interfaces for facilitating interactions between such programs and their host environment

I didn't get it but it looks like an compiled language for web . with the help of JS it can make the web even faster with near-native runtime speed which sounds really cool but well our job is to reverse this not admire it right

## Approach

### 1. Researching disassembly/debugging utitlities:
- wabt/wasm2c
A quick google search yield a wabt/wasm2c . which is a tool used to decompile WebAssembly [binary_format] into a high level c code
after compiling and running the tool it turned out not so much of a help bcs the decompiled code was too hard to read . Exhibit A
```c
u32 w2c_webnative_check_input_0(w2c_webnative* instance, u32 var_p0) {
    ...
  FUNC_PROLOGUE;
  var_i0 = instance->w2c_g0;
  i32_store(&instance->w2c_memory, (u64)(var_i0) + 4, var_i1);
  var_L2: 
    if (var_i0) {goto var_B1;}
    var_i0 = i32_load(&instance->w2c_memory, (u64)(var_i0) + 4u);
    var_i0 = 1u;
    ...

```

I'll spare you the rest of the code . so I needed a new approach
+ ghidra-wasm-plugin
After a second search I found this awesome plugin [ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin) thanks @nneonneo for making this . it helped a lot . anyway . so after installing the extension into Ghidra I was now able to decompile the binary . BINGO

The way WebAssembly works as far as I understand and *please correct me if I'm wrong* is it exposes a certain functions to JS to use which can be found in the Javascript code `webnative.js` . the function name that we need to reverse is called `check_input` you could find it the Exported functions inside of ghidra . and after a nice cleaning up of the function it now looks like this

```c
uint export::check_input(char *input)

{
  byte *operand_addr;
  uint i;
  int incorrect_chars;
  uint payload_idx;
  uint calculated_value;
  char op;
  
  i = 0;
  do {
    if (0xc5 < i) {
      return (uint)(incorrect_chars == 0);
    }
    operand_addr = (byte *)(i * 2 + 0x10000);
    op = *(char *)(i * 2 + 0x10001);
    if (op == '\x01') {
      calculated_value = (uint)*operand_addr ^ (int)input[payload_idx];
    }
    else if (op == '\x02') {
      payload_idx = (uint)*operand_addr;
    }
    else {
      if (op != '\x03') {
        return 0;
      }
      if (calculated_value != *operand_addr) {
        incorrect_chars = incorrect_chars + 1;
      }
    }
    i = i + 1;
  } while( true );
}

```

That's way more readable right . now from now on it's just good old fashioned c code reverse

- Observe that there's an address `ram:0x10000` which marks the start of a payload of some kind 
+ Observe that the loop is 0xc5 iterations . each time we get two bytes . so basically the payload size is 0x18a bytes we'll call this the reciepe 
* For each iteration we have an OP_byte and a OPERAND_byte . the OP specifies what to do and the DATA byte specifies the operand 
    - if the operand is 1:
        calculate the input[payload_idx]^operand
    + if the operand is 2:
        change the payload_idx = operand
    - if operand is 3:
        check the previous calculation to be equal the new data byte if not increment the incorrect_chars which is gonna determine the return value


and with that I leave you guys with my solve script and the flag

```python

flag_reciepe = b'\x3b\x02\x3a\x01\x09\x03\x20\x02\x4b\x01\x7f\x03\x04\x02\x21\x01\x47\x03\x24\x02\x3f\x01\x0f\x03\x3a\x02\x3b\x01\x49\x03\x32\x02\x45\x01\x72\x03\x21\x02\x2b\x01\x68\x03\x3e\x02\x43\x01\x31\x03\x06\x02\x44\x01\x28\x03\x38\x02\x3d\x01\x0d\x03\x28\x02\x3e\x01\x70\x03\x3d\x02\x33\x01\x00\x03\x03\x02\x30\x01\x44\x03\x00\x02\x47\x01\x24\x03\x1f\x02\x15\x01\x47\x03\x08\x02\x38\x01\x61\x03\x1b\x02\x3f\x01\x0b\x03\x0c\x02\x32\x01\x6d\x03\x0f\x02\x23\x01\x67\x03\x25\x02\x43\x01\x0d\x03\x2f\x02\x1b\x01\x77\x03\x1a\x02\x4d\x01\x12\x03\x33\x02\x20\x01\x69\x03\x07\x02\x3e\x01\x0a\x03\x35\x02\x3a\x01\x09\x03\x05\x02\x28\x01\x53\x03\x0d\x02\x2a\x01\x1e\x03\x39\x02\x37\x01\x68\x03\x31\x02\x19\x01\x46\x03\x1d\x02\x46\x01\x73\x03\x09\x02\x3f\x01\x0c\x03\x0a\x02\x45\x01\x37\x03\x2e\x02\x4b\x01\x7c\x03\x15\x02\x1a\x01\x48\x03\x13\x02\x1c\x01\x65\x03\x40\x02\x43\x01\x70\x03\x11\x02\x50\x01\x3c\x03\x3f\x02\x1d\x01\x2f\x03\x0b\x02\x2b\x01\x1e\x03\x01\x02\x1b\x01\x62\x03\x30\x02\x30\x01\x03\x03\x23\x02\x1c\x01\x75\x03\x12\x02\x45\x01\x71\x03\x2c\x02\x39\x01\x50\x03\x2d\x02\x31\x01\x06\x03\x29\x02\x2a\x01\x6e\x03\x26\x02\x41\x01\x1e\x03\x17\x02\x1d\x01\x42\x03\x22\x02\x2f\x01\x18\x03\x1c\x02\x37\x01\x0f\x03\x18\x02\x19\x01\x29\x03\x36\x02\x2a\x01\x75\x03\x0e\x02\x17\x01\x59\x03\x2a\x02\x47\x01\x18\x03\x19\x02\x34\x01\x52\x03\x3c\x02\x14\x01\x42\x03\x27\x02\x23\x01\x17\x03\x41\x02\x3a\x01\x47\x03\x34\x02\x32\x01\x5f\x03\x2b\x02\x4f\x01\x23\x03\x10\x02\x34\x01\x6b\x03\x02\x02\x29\x01\x4a\x03\x1e\x02\x46\x01\x71\x03\x16\x02\x4e\x01\x7b\x03\x37\x02\x18\x01\x2f\x03\x14\x02\x30\x01\x03\x03'


flag                = [0]*0xc5
payload_idx         = 0x0
calculated_value    = 0x0 
incorrect_items     = 0x0

for i in range(len(flag_reciepe)//2):

    operand         = flag_reciepe[(i*2)+0]
    op              = flag_reciepe[(i*2)+1]
    
    if op == 0x1:       # do an xor
        calculated_value = operand
        continue

    elif op == 0x2:     # set payload_idx
        payload_idx = operand
        continue
    
    elif op == 0x3:     # check if the calculated value of the previous XOR is good 
        flag[payload_idx] = calculated_value ^ operand
        continue

    assert("Unreachable block")

flag_str = ''.join([chr(i) for i in flag])

print(flag_str)
```

# cyctf{l4Y3r5_4ND_l4y3R5_0f_4857R4C7i0N_4ND_li77l3_7Im3_70_r3V3r23}

