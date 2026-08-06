#### A simple kernel module that gives user a rootshell. 

Hides module from /sys/module and /proc/modules, /proc/kallsyms as well as kernel tracing files.<br>

```
# git clone https://github.com/carls0n/modrootshell
# cd modrootshell
# make
# sudo insmod modrootshell.ko
# kill -64 31337 [user defined number in source code] gives a rootshell
```

Must have module unhidden to uninstall
```
# kill -63 8000 (or whatever number you defined in source code)
# sudo rmmod modrootshell
```
---
In my paper, 'defeating LKM and LD_PRELOAD rootkits for fun and profit' [https://carls0n.github.io], I talked about the impossibility of using ftrace or even kprobes for your LKM and not registering under /sys/kernel/tracing/enabled_functions. Even if we used kprobes and notrace in our code, we could make the registrations under available_filter_functions vanish, but hooking sys_kill via kprobes still uses the ftrace backend, which is going to register SOMETHING in enabled_functions.<br>

Well...there's more than one way to skin a cat, as they say. There are more options available for hooking sys_kill. Here, in order to hook sys_kill, this module registers a temporary kprobe to locate the non-exported kallsyms_lookup_name function. Once we extract its address, the kprobe is immediately unregistered. We then use kallsyms_lookup_name to resolve the memory address of __x64_sys_kill and deploy our inline hook. This method allows us to bypass the ftrace based enabled_functions file. Nothing registered there. Then, we use notrace in our code for our functions, which will successfully hide them from available_filter_functions.<br>

Of course, the module starts out hidden. From both /sys/module and /proc/modules. You might already be wondering, if we cant detect this module via /sys/kernel/tracing/enabled_functions or /sys/kernel/tracing/available_filter_functions, then how do we find it? Short of running volatility and looking for it in memory.<br>

Actually, it's quite simple if you just know this one thing. Here we are going to get the address of __x64_sys_kill:
```
# sudo grep -w "__x64_sys_kill" /proc/kallsyms
ffffffff8fd87790 T __x64_sys_kill
```
Copy the address above, just the first series of letters and numbers

Next, type the following:<br>
```
# sudo gdb --core=/proc/kcore
```
At the prompt, type the following, which should give us the first 5 instructions starting at the address we got from kallsyms for __x64_sys_kill. Just put an 0x in front of it. That tells gdb that the address is going to be in hexadecimal format.<br>
```
(gdb) x/5i 0xffffffff8fd87790
   0xffffffff8fd87790:	movabs $0xffffffffc04a1200,%rax
   0xffffffff8fd8779a:	jmp    *%rax
   0xffffffff8fd8779c:	mov    $0x1,%esi
   0xffffffff8fd877a1:	push   %rbx
   0xffffffff8fd877a2:	sub    $0x38,%rsp
(gdb)
```
If the above is what you have, you found it! Pay particular attention to the first two instructions. This absolutely proves that sys_kill is hooked!<br>

Now, lets look for cmp instructions at the address found above.
```
(gdb) pipe x/15i 0xffffffffc04a1200 | grep cmp
   0xffffffffc04a1220:	cmp    $0x40,%edx
   0xffffffffc04a1225:	cmp    $0x7a69,%rcx
   0xffffffffc04a1232:	cmp    $0x3f,%edx
   0xffffffffc04a123b:	cmp    $0x1f40,%rcx
(gdb)
   ```
Look at the third cmp instruction. The decimal of 0x3f is 63. The next cmp instruction is 0x1f40, which is 8000. This is our kill signal and magic number to unhide the module so that we can remove it! The first and second cmp instructions represent 64 and 31337. Kill signal and magic number to get a rootshell.

If you need to convert the hexadecimal to decimal, it's simple. (p as in print, d as in decimal)
```
(gdb) p/d 0x3f
$1 = 63
(gdb) p/d 0x1f40
$2 = 8000
(gdb)
```
So, after finding and executing the kill signal and magic number,
```
kill -63 8000
```

Look at lsmod. The newly revealed module should be at the top of the list. Remove it using:
```
sudo rmmod module_name
```

If you have access to the .ko file, you can simply run the following:
```
# objdump -d ./modrootshell.ko | grep -E cmp
 223:	83 f8 40             	cmp    $0x40,%eax
 228:	48 81 fa 69 7a 00 00 	cmp    $0x7a69,%rdx
 235:	83 f8 3f             	cmp    $0x3f,%eax
 23e:	48 81 fa 40 1f 00 00 	cmp    $0x1f40,%rdx
```
If you dont have have kcore<br>
```
# ls -l /proc/kcore
```
then your kernel was compiled without support for it. Support would require recompiling the kernel but is out of the scope of this text.

