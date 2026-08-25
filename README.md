
### Breaking Systems. Documenting the Why. Elevating Security.

![Binary Exploitation](https://img.shields.io/badge/Binary%20Exploitation-ef4444?style=flat-square&logoColor=white)
![Reverse Engineering](https://img.shields.io/badge/Reverse%20Engineering-f97316?style=flat-square&logoColor=white)
![Cryptanalysis](https://img.shields.io/badge/Cryptanalysis-a855f7?style=flat-square&logoColor=white)
![Web Exploitation](https://img.shields.io/badge/Web%20Exploitation-3b82f6?style=flat-square&logoColor=white)
![VM Exploitation](https://img.shields.io/badge/VM%20Exploitation-f59e0b?style=flat-square&logoColor=white)
![Exploit Dev](https://img.shields.io/badge/Exploit%20Development-22c55e?style=flat-square&logoColor=white)

---

A collection of deep-dive offensive security analyses and exploitation writeups. Each entry documents a real attack — the methodology, the reasoning, the dead ends, and the techniques that worked. Written to be technically precise and useful beyond the specific target.

Every writeup is structured around four questions:
- What is the vulnerability and why does it exist?
- What does a working exploit actually look like?
- Which protections were bypassed and how?
- What does this mean for defenders?

---

## Writeups

### [Advanced Memory Corruption: A Multi-Stage Binary Exploitation Case Study](Write-ups/memory-corruption-multi-stage/)

> `Binary Exploitation` · `PIE` · `Stack Canary` · `NX` · `Partial RELRO`

A four-stage exploit chain against a modern protected binary. The 84-byte overflow never reaches the canary — instead, both `strcpy` arguments are manipulated to create an arbitrary write primitive. Two information leaks (`.bss` and stack), a return address overwrite, and a GOT hijack to a built-in `mprotect_stack` function make the stack executable without a ROP chain.

**Protections defeated:** PIE · Stack Canary · NX · Partial RELRO

---

### [Five Layers, One Flaw: Breaking a Multi-Layer Anti-Automation System](Write-ups/anti-automation-bypass/)

> `Reverse Engineering` · `Cryptanalysis` · `Binary Parsing` · `Constraint Solving`

A five-layer anti-automation system — complex binary format, sequence validation, SHA-256 hashing, cryptographic salting, and obfuscation — fully compromised in under one second. Not through a weakness in SHA-256, but because the entire input space is 25 elements. The salt is stored next to the hash. The secret is in plaintext. Strong crypto applied to the wrong problem provides no security.

**Core insight:** Cryptographic strength is context-dependent. A 25-element input space makes SHA-256 trivially brute-forceable in microseconds regardless of salting.

---

### [Chain Reaction: Full Compromise of a Secure Chat System](Write-ups/chain-reaction-secure-chat/)

> `Web Exploitation` · `Cryptography` · `Binary Exploitation` · `XSS` · `AES-ECB`

A five-stage attack chain across completely different vulnerability classes. SQL injection establishes the foothold. Stored XSS becomes the pivot — delivering both a Diffie-Hellman parameter manipulation attack and a buffer overflow payload inside the administrator's browser. AES-ECB's determinism enables plaintext recovery one block at a time. Each stage creates the conditions for the next.

**Attack chain:** SQL Injection → Stored XSS → DH Manipulation → ECB Block-Matching → Buffer Overflow

---

### [Emulator Breakthrough: Reverse Engineering a Randomized Virtual Machine](Write-ups/emulator-breakthrough/)

> `Reverse Engineering` · `VM Exploitation` · `ISA Reconstruction` · `Toolchain Development`

A custom virtual machine with a fully randomized ISA — opcodes, register encodings, and instruction byte ordering all shuffled per instance. The exit syscall leaks internal register state through the process exit code, creating an oracle that reconstructs the entire ISA in 336 targeted probes instead of 393,216 blind attempts. A purpose-built assembler, disassembler, and interpreter were developed to write and verify multi-stage payloads under severe register constraints.

**Core insight:** The exit code is an information disclosure channel. Every interface is an attack surface.

---

### [Ghost Page: Locating Erased Memory via Prefetch Side-Channel and Exfiltrating Through Exit Status](Write-ups/prefetch-side-channel/)

> `Microarchitectural Attack` · `Side-Channel` · `x86-64 Assembly` · `ASLR Bypass`

A page is allocated at a randomized address, a secret written into it, then every pointer zeroed — no surviving references anywhere in the process. Injected shellcode has access to one syscall only: `exit`. The attack locates the erased page using `prefetcht2` timing discrimination (28× amplified, with signal inversion accounted for), verifies it via known-prefix comparison, and exfiltrates contents one byte at a time through the process exit code. Parallel retry workers handle measurement noise without hardening single-shot reliability.

**Core insight:** `prefetcht2` does not fault on unmapped addresses — but it still triggers address translation. That translation cost is the side channel.

---

## Blogs

> 🔧 **Coming soon** — concept-focused writing on vulnerability classes, cryptographic failures, and exploitation techniques. Each post will explore the *why* behind the attacks documented in the writeups above.

---

## Repository Structure

```
offensive-security-research/
│
├── README.md
│
├── Write-ups/
│   ├── memory-corruption-multi-stage/
│   ├── anti-automation-bypass/
│   ├── chain-reaction-secure-chat/
│   └── emulator-breakthrough/
│   └── prefetch-side-channel/
│
└── blogs/                          ← coming soon
```

---

## Technical Areas

| Area | Topics |
|------|--------|
| **Binary Exploitation** | Buffer overflows, GOT hijacking, return address overwrite, shellcode development |
| **Reverse Engineering** | Static analysis (Ghidra), dynamic analysis (GDB), custom ISA reconstruction, VM internals |
| **Cryptanalysis** | AES-ECB block-matching oracle, Diffie-Hellman parameter manipulation, hash brute-force against constrained input spaces |
| **Web Exploitation** | SQL injection, stored XSS, browser-as-attack-vector |
| **Exploit Development** | Multi-stage chains, pwntools, position-independent shellcode, register-constrained payloads |

---

## Contact

**Youssef Hasan**  
Offensive Security · Vulnerability Research · Secure Systems

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/youssef-essam12/)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Youssef-0007)
[![Email](https://img.shields.io/badge/Email-EA4335?style=flat-square&logo=gmail&logoColor=white)](mailto:youssef.e.hasan12@gmail.com)

---

*All research conducted in authorized environments for educational and professional development purposes.*
