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

## Reverse Engineering

## DFIR - Digital Forensics and Incident Response

## Malware

## Web

## Mobile (Android/iOS)

## Miscellaneous

## Fingerpinting

### DirBuster / GoBuster / FeroxBuster

## Privilege Escalation

### PEASS-ng
