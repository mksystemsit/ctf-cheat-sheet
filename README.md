# CTF Cheat Sheet

This cheat sheet provides many tools, tips and tricks that can be useful in CTF (capture the flag) challenges.

## Distros and Frameworks

| Distribution | Link | Description |
| ------------ | ---- | ----------- |
| Kali Linux | [kali.org](https://www.kali.org) | Linux distro loaded with an arsenel of pentesting tools and documentation. The most popular pentesting distro. |
| ParrotSec | [parrotsec.org](https://parrotsec.org) | Linux distro loaded with pentesting tools, similar to Kali. Parrot is more lightweight and has less tools installed out of the box, so may be more beginner-friendly if you don't like bloated distros. |
| Remnux | [remnux.org](https://remnux.org) | A Linux distro loaded with tools for reverse-engineering and malware analysis. |
| Docker | [docker.com](https://docker.com) | A containerisation platform used to run self-contained binaries and services in their own sandboxed environment. Similar to a virtual machine but uses far less resources, at the expense of sharing the same kernel as the host operating system. Many pentesting tools have pre-made containers in the Docker registry. |

## Reference Tools and Websites

| Name | Site | Description |
| ---- | ---- | ----------- |
| GTFOBins | [gtfobins.github.io](https://gtfobins.github.io) | Curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems. Useful for privilege escalation on a box where you have to live off the land. |
| HackTricks | [book.hacktricks.xyz](https://book.hacktricks.xyz) | GitBook of tricks, techniques and tools learned by the author during CTFs, IRL engagements and research. |
| PentestMonkey Cheat Sheets | [pentestmonkey.net](https://pentestmonkey.net/category/cheat-sheet) | A collection of cheat sheets. Nuff said, check back regularly for updated content. |
| CrackStation | [crackstation.net](https://crackstation.net) | Useful site for checking found hashes against known hash lists and rainbow tables. |
| RevShells | [revshells.com](https://revshells.com) | Generate syntax for spawning reverse shells depending on desired shell prompt and language used in RCE exploits. |
| PayloadsAllTheThings | [GitHub: PayloadsAllTheThings](https://github.com/swisskeyrepo/PayloadsAllTheThings) | A list of useful payloads and bypasses for Web Application Security. Available in the Kali repos. |
| SecLists | [GitHub: SecLists](https://github.com/danielmiessler/SecLists) | A collection of multiple types of lists used during security assessments, collected in one place. Typically installed by default in Kali and Parrot, and available in the Kali repos. |


## OSINT - Open Source INTelligence
### I'm Stuck!
If you're ever stuck on an OSINT challenge, look at the [OSINT Framework](https://osintframework.com) website for a tool that you can use to run your breadcrumb through.

If you want to know who an email address is registered to, use the [EPIEOS Email Lookup](https://tools.epieos.com/email.php) to run an email address and gain further intel. The site also runs the email through holehe and returns results from other common online services that the email address is used on.

Use this especially for Gmail accounts, as the tool will return the Google account details for that address. This also works for Google Workspace (G Suite) addresses.

## Reverse Engineering and Binary Exploitation

### Tools
| Name | Link | Description |
| ---- | ---- | ----------- |
| radare2 | [radare2](https://rada.re/n/radare2.html) | A free/libre toolchain for easing several low-level tasks like forensics, software reverse engineering, exploiting, debugging, etc. Installed by default in Kali |
| Cutter | [cutter.re](https://cutter.re) | An open-source reverse engineering platform powered by the Rizin framework (Rizin is a fork of radare2). Available for download as an AppImage on Linux, as well as Windows and MacOS. |
| dnspy | [GitHub: dnSpy](https://github.com/dnSpy/dnSpy) | A debugger and .NET assembly editor. Requires Windows - use ilSpy if you want to debug on Linux. |
| Immunity Debugger | [Immunity Debugger](https://immunityinc.com/products/debugger/) | A lightweight debugger geared for InfoSec professionals, with a Python API for easy extensibility. |

### Fingerprinting a Binary
When looking at a file that's not immediately obvious as to what it is, run the `file` command against it and you'll be given a best guess as to what the file is.

```console
mk@0x01:~$ file cmus
cmus: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d840331586ee2dab927367939ac426fb10a2a0ea, for GNU/Linux 3.2.0, stripped
```

The example above is the output for the cmus music player, look at your own output for what to reach for next.

**Shortcut**: If the file output references .NET or Mono, you have a .NET binary and should jump straight to using dnSpy or ilSpy to disassemble and/or decompile the binary.

### Static Analysis

There are several ways to go about static analysis when dealing with binaries.
- You can hexdump the binary data
- You can use a decompiler or disassembler to see the assembly code
- You can run `strings` to dump out any text strings from the binary and see if anything stands out
- You can run the binary through a tool like **radare2** or **Cutter** to examine the contents of the binary.

Installing and running Cutter will give you the best of all of these, as you can see all of the above information within one utility. You still have the option of dropping to the command line and analysing the bits that way, but if you're after a single place to extract the above data, Cutter may be the best tool for you.

### Dynamic Analysis

The dynamic analysis is more variable in its execution, as you're literally running the binary and looking at its activity via a debugger. The tools you use will depend on the inteneded operating system and CPU architecture, as well as the source programming language and the compiler used. There are many debuggers available for Windows (IDA Pro, SoftIce, Immunity Debugger), and Linux typically uses the GCC libraries and the gdb binary to debug ELF binaries.

## DFIR - Digital Forensics and Incident Response

## Malware

## Web

## Mobile (Android/iOS)

## Miscellaneous

## Fingerpinting

### DirBuster / GoBuster / FeroxBuster

## Privilege Escalation

### PEASS-ng
