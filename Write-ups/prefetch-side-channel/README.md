![Banner](banner.png)

---

# Ghost Page: Locating Erased Memory via Prefetch Side-Channel and Exfiltrating Through Exit Status

> **Category:** Microarchitectural Attack · Side-Channel &nbsp;|&nbsp; **Technique:** `prefetcht2` timing oracle · amplified TLB discrimination · exit-status exfiltration &nbsp;|&nbsp; **Reference:** Gruss et al., *Prefetch Side-Channel Attacks* (CCS 2016)

---

## Executive Summary

A process allocates a page at a randomized address, writes a secret into it, then zeroes every reference — no pointers survive on the stack, in registers, or in globals. Injected shellcode runs inside the target's address space but is restricted to a single syscall: `exit`. No `write`, `open`, `read`, or any other output mechanism is available.

The challenge: locate a page whose address is completely unknown, verify it contains the right data, and exfiltrate its contents — using nothing but CPU cache timing and a process exit code.

**Key skills demonstrated:**
- Reverse engineering of randomized allocation logic to bound the search space
- Non-faulting memory probing via `prefetcht2` timing discrimination
- Signal amplification and threshold calibration for microarchitectural side channels
- Single-byte exfiltration through process exit status
- Noise-tolerant parallel retry architecture

---

## The Constraints

```
What exists:
  · One mapped page at an unknown address
  · Known secret prefix (for verification)
  · exit() syscall only — no read, write, open

What doesn't exist:
  · Any pointer to the page (all zeroed after allocation)
  · Any direct output channel
  · Any debugging interface

Goal:
  · Find the page
  · Confirm it's the right one
  · Exfiltrate its contents one byte at a time
```

This is not a standard memory disclosure. The page has no surviving references anywhere in the process — it exists only as mapped physical memory with no logical path to it.

---

## Phase 1 — Reverse Engineering the Address Space

Static analysis of the allocation logic reveals the generator:

```c
local_30 = 0;
read(urandom_fd, &local_30, 3);               // 24 bits of randomness
local_30 = (void *)((long)local_30 << 0x10);  // left-shift by 16
local_28 = mmap(local_30, 0x1000,
                PROT_READ | PROT_WRITE,
                MAP_FIXED_NOREPLACE, -1, 0);
if (0xffff < (long)local_28 && (long)local_28 < 0x10000000000) {
    read(secret_fd, local_28, 0x40);
    close(secret_fd);
    local_28 = 0;
    local_30 = 0;    // all references zeroed
}
```

**Derived properties:**

| Property | Value | Implication |
|----------|-------|-------------|
| Randomness | 24-bit left-shifted by 16 | Base always a multiple of `0x10000` |
| Address range | `(0x10000, 0x10000000000)` | ~1 billion candidates at `0x1000` step |
| Page size | `0x1000` (4 KiB) | Single page, `rw-` permissions |
| Scan granularity | `0x10000` steps sufficient | 16× fewer probes than `0x1000` stepping |

**Critical optimization:** because the base is always `0x10000`-aligned (24-bit random × 64 KiB), stepping the scan by `0x1000` checks 16 addresses for every 1 that could possibly be valid. Stepping by `0x10000` reduces probe count by 16× with no correctness cost — only addresses at that alignment can be the target.

---

## Phase 2 — The Prefetch Oracle

### Why Not Just Read the Address?

Dereferencing an unmapped address causes a fault — and with millions of candidates to probe, one fault crashes the process. A non-faulting probe mechanism is required.

### `prefetcht2` as a Non-Faulting Probe

`prefetcht2` is a cache-hint instruction: it asks the CPU to bring a cache line into L2. Architecturally it is a *hint* — it **does not fault on invalid addresses**. But executing it still forces the CPU to perform address translation (TLB lookup → page-table walk on a miss), and that translation cost is measurable:

```
Mapped address:    TLB lookup → cache line fetched → translation cached
Unmapped address:  TLB lookup → page-table walk aborts → nothing cached

Δ cycles between the two cases = the side-channel signal
```

### Timing Measurement with Baseline Subtraction

Raw `rdtsc` measurements are dominated by serialization cost and pipeline noise. Each iteration subtracts a same-iteration baseline to cancel fixed overhead:

```asm
; Baseline — apparatus cost only, no memory access
lfence
rdtsc → T_a
lfence
rdtsc → T_b
baseline = T_b - T_a

; Prefetch measurement
lfence
rdtsc → T_c
prefetcht2 [addr]         ; non-faulting probe
lfence
rdtsc → T_d
prefetch_cost = T_d - T_c

delta = prefetch_cost - baseline
```

> ⚠️ **Wraparound caveat:** subtraction is unsigned. If `prefetch_cost < baseline` due to scheduler jitter, the result wraps to a large value. This edge case should be guarded explicitly — treat an implausibly large delta as noise rather than a definitive classification.

> ⚠️ **Preemption caveat:** `rdtsc` advances across context switches. A scheduler preemption between timestamp reads is indistinguishable from a slow memory access. `rdtscp` (which also reads the current core ID) allows detection of core migration between reads and is a common mitigation.

### Signal Amplification

A single `prefetcht2` produces a signal of tens of cycles — comparable to measurement noise. Repeating the prefetch 28× against the same address amplifies the cumulative difference into a reliably distinguishable range.

**Important: amplification inverts the signal direction.**

```
Single prefetch:
  Mapped   → full translation cost → SLOWER → larger delta
  Unmapped → walk aborts early     → FASTER → smaller delta
  Classification: large delta = mapped

Repeated prefetch (×28):
  Mapped   → first probe pays translation, remaining 27 hit TLB cache → FASTER cumulative
  Unmapped → no TLB entry to cache, each of 28 attempts re-walks    → SLOWER cumulative
  Classification: small delta = mapped  ← INVERTED
```

This inversion is the most subtle aspect of the attack. A threshold tuned for a single-probe measurement must be recalibrated after changing the amplification factor. Best practice: probe a known-mapped address (e.g. the shellcode's own stack) and a known-unmapped address, log raw deltas for each, and pick a threshold between the two observed clusters.

```
                    Timing signal across address space:

  Δ cycles
     ▲
     │     unmapped        mapped    unmapped    mapped
     │  ___________________  _   ___________________  _
     │                     \/                        \/
     │
     └──────────────────────────────────────────────────▶ address
                           ↑                        ↑
                      TLB cache hit             TLB cache hit
                      (small delta)             (small delta)
```

---

## Phase 3 — Content Verification

A timing match alone isn't sufficient — the target process has other mapped pages (stack, heap, loader, libc) that also pass the timing check. The candidate page's contents are compared against the known secret prefix:

```asm
; Compare first 8 bytes against known prefix (little-endian)
mov rax, 0x6c6c6f632e6e7770
cmp rax, qword ptr [rdi]
jne .next

; Compare next 4 bytes
mov eax, 0x7b656765
cmp eax, dword ptr [rdi+8]
jne .next

; Both match — this is the target page
```

Only a page passing **both** the timing check and the content check is treated as the target. This eliminates false positives from other mapped regions.

---

## Phase 4 — Exfiltration via Exit Status

With only `exit` available, output is one byte per process invocation:

```asm
movzx rdi, byte ptr [rdi + POS]   ; load one byte at position POS
mov   rax, 60                      ; exit syscall number
syscall
```

The driving script:
1. Injects shellcode with a specific `POS` baked in
2. Reads the child process's exit code (`$?`)
3. Appends the byte to a growing buffer
4. Repeats for `POS = 0, 1, 2, ...` until the closing delimiter appears

Each invocation is fully self-contained — it re-derives the target page's address from scratch, since ASLR rerandomizes on every process spawn and nothing persists between runs.

```
Per-byte flow:

  spawn process
       │
       ▼
  scan address space (step 0x10000)
  prefetcht2 × 28 per candidate
       │
       ▼
  timing check → candidate
       │
       ▼
  content verify → confirmed page
       │
       ▼
  exit(page[POS])
       │
       ▼
  driver reads $? → one byte recovered
```

---

## Noise Handling: Parallel Retry

The side channel is inherently noisy — a given probe may misclassify due to `rdtsc` jitter, scheduler preemption, or a borderline threshold. Rather than hardening single-shot reliability, the driver runs several worker processes **concurrently** per byte position and discards any result that isn't a printable ASCII byte, immediately spawning a replacement:

```
For each byte position:
  spawn N workers in parallel
  collect exit codes
  discard non-printable results
  first valid printable result → accepted
  stop when closing delimiter received
```

This converts an unreliable per-attempt signal into a reliable aggregate one. The cost is extra process spawns — acceptable given how cheap each individual attempt is relative to engineering time spent hardening single-shot accuracy.

---

## Attack Flow Summary

```
1. REVERSE ENGINEERING
   └─ Derive address range: (0x10000, 0x10000000000)
   └─ Derive scan step: 0x10000 (24-bit × 64KiB alignment)

2. NON-FAULTING SCAN
   └─ For each candidate in range (step 0x10000):
       └─ Measure baseline (rdtsc, no access)
       └─ Execute prefetcht2 × 28
       └─ Compute delta
       └─ Small delta → likely mapped → verify

3. CONTENT VERIFICATION
   └─ Compare candidate[0:8] against known prefix
   └─ Compare candidate[8:12] against known prefix
   └─ Both match → target confirmed

4. EXFILTRATION
   └─ exit(page[POS]) → driver reads $?
   └─ Repeat for each byte position
   └─ Stop at closing delimiter
```

---

## Key Takeaways

**Non-faulting probes turn hardware hints into oracles.** `prefetcht2` exists to improve cache performance. It also reveals whether an address is mapped — without ever faulting, without ever touching the data. Any architectural "hint" that triggers address translation is a potential side channel.

**Signal direction can invert under amplification.** A single probe and 28 repeated probes produce signals with opposite discrimination directions. Threshold values calibrated for one measurement regime do not transfer to another — always recalibrate empirically against known-mapped and known-unmapped addresses.

**Static analysis bounds dynamic search.** Reverse engineering the allocation logic reduced an ~1-billion-candidate blind scan to a targeted scan of ~16 million candidates, each with maximum 336 probes — a 16× reduction from understanding the address generator's alignment properties alone.

**Constrained output channels are still output channels.** A single byte per process invocation through an exit code is enough — if the attacker controls which byte is returned and can spawn processes repeatedly. Restricting syscalls is a meaningful mitigation only when every indirect output channel (timing, exit codes, resource exhaustion) is also considered.

**Noise tolerance through redundancy beats noise elimination through precision.** Hardening a single probe to be reliable under all scheduler conditions is an engineering challenge with diminishing returns. Running parallel workers and taking the first valid result trades process spawning cost for engineering simplicity — usually the right trade.

---

## Tools

| Tool | Use |
|------|-----|
| Ghidra | Binary reverse engineering, allocation logic reconstruction |
| GDB | Static inspection, address space layout analysis |
| x86-64 Assembly | Shellcode: `prefetcht2`, `rdtsc`, `lfence`, content comparison, exit syscall |
| Python 3 | Driver script: parallel worker management, byte collection, delimiter detection |

---

## Reference

Gruss, D., Maurice, C., Mangard, S. (2016). *Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR*. ACM CCS 2016.

---

*Analysis conducted as part of an educational offensive security research program. All techniques documented for research and defensive purposes in an authorized environment.*
