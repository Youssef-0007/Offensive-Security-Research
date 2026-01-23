# Reverse Engineering & Exploiting the Yan85 Virtual Machine

**A Deep Dive into Custom ISA Discovery, Toolchain Development, and VM Exploitation**

---

## Executive Summary

The Yan85 emulator series presents a sophisticated reverse engineering challenge: a custom-built virtual machine with a **randomized Instruction Set Architecture (ISA)**. This write-up documents the complete methodology—from initial reconnaissance to full exploitation—showcasing the intersection of binary analysis, vulnerability research, and automated tool development.

**Key Achievements:**
- Reconstructed a completely randomized ISA through static and dynamic analysis
- Identified and exploited a critical information disclosure vulnerability in syscall implementation
- Developed a fully-functional assembler/disassembler with modular architecture
- Successfully chained multi-stage syscalls under severe register constraints

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Phase I: Reconnaissance & ISA Discovery](#phase-i-reconnaissance--isa-discovery)
3. [Phase II: The Exit Oracle Vulnerability](#phase-ii-the-exit-oracle-vulnerability)
4. [Phase III: Automated Toolchain Development](#phase-iii-automated-toolchain-development)
5. [Phase IV: Exploitation Under Constraints](#phase-iv-exploitation-under-constraints)
6. [Educational Takeaways](#educational-takeaways)
7. [Conclusion](#conclusion)

---

## Challenge Overview

The Yan85 series (culminating in `yansanity-hard`) implements a **virtual machine emulator** with the following characteristics:

- **Custom ISA**: 8 opcodes with randomized instruction encoding
- **3-Byte Instruction Format**: Opcode and two arguments, with randomized ordering
- **Register-Based Architecture**: 7 registers (general-purpose, stack pointer, instruction pointer, flags)
- **Memory-Mapped I/O**: Syscall interface for file operations
- **Randomization**: Each challenge iteration shuffles opcode values, register mappings, and instruction layouts

This design forces researchers to treat the binary as a **black box**, requiring systematic discovery of the entire architecture.

---

## Phase I: Reconnaissance & ISA Discovery

### 1.1 Static Analysis with Ghidra

The initial approach focused on identifying the VM's core components through static analysis:

#### Finding the VM Loop

Using Ghidra's decompiler, I located the **Fetch-Decode-Execute** loop—the heart of any emulator. The pattern was recognizable:

```c
  byte bVar1;
  
  do {
    bVar1 = *(byte *)(param_1 + 0x405);
    *(byte *)(param_1 + 0x405) = bVar1 + 1;
    interpret_instructions(param_1,(ulong)*(uint3 *)((long)(int)(uint)bVar1 * 3 + param_1));
  } while( true );

```

**Key Discovery**: The VM state structure maintains registers at **fixed offsets** from a base pointer. For example:
- `vm_state + 0x400` → Register A
- `vm_state + 0x405` → Stack Pointer
- `vm_state + 0x406` → Instruction Pointer

However, these offset mappings change between challenge iterations, requiring dynamic discovery.

#### Instruction Format Analysis

The decompiler revealed that each 3-byte instruction chunk packs three components, but their **ordering is randomized**:

- **Possible Layouts**: `op|a1|a2`, `a1|op|a2`, `a2|a1|op`, `a1|a2|op`, `op|a2|a1`, `a2|op|a1`
- **Challenge**: Without knowing the layout, raw bytecode is meaningless

### 1.2 Dynamic Analysis with GDB

**Challenge**: The binary runs with **SUID permissions**, which severely limits GDB's capabilities:
- Cannot attach to running processes
- Cannot set breakpoints in executing code
- Standard debugging workflows are restricted

**Workaround Strategy**: I used GDB in a **static exploration mode**:

```bash
# Load binary without execution
gdb ./yan85

# Examine memory sections
info files
info sections

# Explore .rodata for hardcoded values
x/100bx 0x<rodata_address>

# Analyze .text section for code patterns
disassemble <function_address>

# Search for opcode/register candidate values
find 0x<start>, 0x<end>, 0x1, 0x2, 0x4, 0x8
```

**Valuable Findings**:
- **Opcode candidate values** in lookup tables within `.rodata`
- **Register offset mappings** in VM initialization code
- **Syscall dispatch tables** revealing syscall number candidates
- **String constants** like "/flag" used for validation

While I couldn't single-step through VM execution due to SUID restrictions, GDB was invaluable for **static binary inspection** and **memory layout understanding**—complementing Ghidra's high-level analysis with low-level byte-accurate views.

**The Breakthrough**: I needed an automated oracle to leak internal VM state beyond static analysis.

---

## Phase II: The Exit Oracle Vulnerability

### 2.1 Vulnerability Discovery

While analyzing syscall handlers in Ghidra, I identified a **critical design flaw** in the exit implementation:

```c
// Syscall dispatcher
if ((syscall_mask & current_instruction) != 0) {
    exit_sys(vm_state, *(undefined1 *)(vm_state + 0x400));
}

// Exit syscall handler
void exit_sys(undefined8 param_1, int param_2) {
    /* VULNERABILITY: VM register value directly controls process exit code */
    exit(param_2);
}
```

**The Issue**: The emulator passes a VM register value directly to the native `exit()` syscall. In Unix systems, the exit code is accessible externally via `$?` in the shell.

### 2.2 Exploitation Mechanism

This creates an **information disclosure oracle**:

```
VM Register A → exit(value) → Shell $? → External Observer
```

**Attack Vector**:
1. Load a known value into Register A using the `IMM` (immediate load) instruction
2. Trigger the exit syscall
3. Check the process exit code (`echo $?`)
4. If the exit code matches the loaded value, we've confirmed:
   - The opcode for `IMM`
   - The register encoding for `A`
   - The position of opcode/arguments in the 3-byte instruction

### 2.3 Systematic ISA Discovery

With this oracle, I automated the entire ISA reconstruction. **Key insight**: The search space is constrained—not arbitrary 0x00-0xFF ranges, but rather **specific valid opcode/register values** that exist in the VM implementation.

Through static analysis, I identified the **candidate sets**:
- **8 possible opcodes**: IMM, ADD, STK, STM, LDM, CMP, JMP, SYS (each with a specific byte value)
- **7 possible registers**: a, b, c, d, s, i, f (each with a specific byte encoding)
- **6 possible instruction layouts**: Different orderings of opcode|arg1|arg2

```python
# Pseudocode for targeted ISA discovery
MARKER_VALUE = 0x42

# Known opcode candidates from static analysis
OPCODE_CANDIDATES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]
REGISTER_CANDIDATES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40]
LAYOUT_CANDIDATES = ["op_a1_a2", "a1_op_a2", "a2_op_a1", 
                     "a2_a1_op", "a1_a2_op", "op_a2_a1"]

for opcode in OPCODE_CANDIDATES:
    for reg in REGISTER_CANDIDATES:
        for layout in LAYOUT_CANDIDATES:
            # Construct instruction: IMM reg, MARKER_VALUE
            instruction = pack_instruction(layout, opcode, reg, MARKER_VALUE)
            
            # Construct payload: instruction + exit syscall
            payload = instruction + exit_syscall_bytes
            
            # Execute and check oracle
            exit_code = run_vm(payload)
            
            if exit_code == MARKER_VALUE:
                print(f"[+] Found IMM opcode: 0x{opcode:02x}")
                print(f"[+] Found Register A: 0x{reg:02x}")
                print(f"[+] Instruction layout: {layout}")
                return opcode, reg, layout
```

**Search Space Efficiency**: Instead of 256 × 256 × 6 = 393,216 attempts, the targeted approach requires only **8 × 7 × 6 = 336 maximum attempts**—a ~1000x reduction.

**Results**: Within seconds, I had:
- ✅ IMM opcode value (from the 8 candidates)
- ✅ Register A encoding (from the 7 candidates)
- ✅ Instruction byte ordering (from the 6 layouts)

Once I had IMM and Register A, I could systematically discover other opcodes by:
- Loading test values into registers
- Performing operations (ADD, CMP, etc.)
- Using exit to leak results
- Inferring opcode semantics from observed behavior
- Mapping each discovered opcode to its corresponding candidate value

---

## Phase III: Automated Toolchain Development

### 3.1 Design Philosophy

Manual hex-editing is infeasible for complex VM payloads. A robust toolchain requires:

1. **Modularity**: Support for randomized ISA configurations
2. **Abstraction**: Human-readable assembly syntax
3. **Verification**: Disassembler for debugging generated payloads

### 3.2 Assembler Architecture

The core challenge was handling **six possible instruction layouts** with a single codebase:

```python
ORDER_MAPS = {
    "op_a1_a2": {"opcode": 0, "arg1": 1, "arg2": 2},
    "a1_op_a2": {"arg1": 0, "opcode": 1, "arg2": 2},
    "a2_op_a1": {"arg2": 0, "opcode": 1, "arg1": 2},
    "a2_a1_op": {"arg2": 0, "arg1": 1, "opcode": 2},
    "a1_a2_op": {"arg1": 0, "arg2": 1, "opcode": 2},
    "op_a2_a1": {"opcode": 0, "arg2": 1, "arg1": 2}
}

# Single configuration variable
CURRENT_ORDER = "a2_a1_op"  # Update per challenge
```

**Layout Abstraction**:
```python
def pack_layout(self, v_op, v_a1, v_a2):
    """Dynamically pack instruction based on current layout"""
    layout = ORDER_MAPS[CURRENT_ORDER]
    result = [0, 0, 0]
    result[layout["opcode"]] = v_op
    result[layout["arg1"]] = v_a1
    result[layout["arg2"]] = v_a2
    return bytes(result)
```

This design allows **instant reconfiguration** for new challenge iterations—just update `CURRENT_ORDER` and reassemble.

### 3.3 Assembly Syntax

The assembler supports intuitive syntax:

```assembly
IMM a 0x2f          # Load '/' into register a
STM *d a            # Store value at memory[d]
STK NONE b          # Push register b onto stack
STK c NONE          # Pop stack into register c
SYS 0x4 a           # Invoke open() syscall, result in a
JMP E i             # Jump if equal flag set
```

### 3.4 Disassembler & Interpreter

For debugging, I implemented a **full VM interpreter** that:
- Decodes bytecode into human-readable assembly
- Simulates execution with register/memory state tracking
- Displays state transitions for each instruction

Example output:
```
0000: [A=0x00 B=0x00 C=0x00 D=0x00 S=0x00 I=0x00 F=0x00]
      IMM a 0x2f
  [EXEC] Loaded 0x2f into register a

0003: [A=0x2f B=0x00 C=0x00 D=0x00 S=0x00 I=0x01 F=0x00]
      STM *d = a
  [EXEC] Memory[0x00] = 0x2f
```

This was **critical** for verifying complex payloads before deployment.

---

## Phase IV: Exploitation Under Constraints

### 4.1 The Challenge: Multi-Stage Syscall Chain

The `yansanity-hard` variant requires reading `/flag` and writing to stdout—a three-syscall sequence:

```
OPEN("/flag") → READ(fd, buffer, size) → WRITE(stdout, buffer, size)
```

**The Constraint Problem**:
- `OPEN` returns file descriptor into a register (e.g., Register A)
- `READ` requires three arguments: fd, buffer address, size
- With only 4-7 general-purpose registers, preparing `READ` arguments **overwrites the fd from OPEN**

### 4.2 Solution: Stack-Based State Preservation

The `STK` (stack) opcode provides temporary storage:

**Exploitation Flow**:

```assembly
# ===== Stage 1: Build "/flag" string in memory =====
IMM d 0x00          # d = buffer address
IMM a 0x2f          # a = '/'
STM *d a            # memory[0] = '/'
IMM a 0x66          # a = 'f'
IMM d 0x01
STM *d a            # memory[1] = 'f'
# ... repeat for 'l', 'a', 'g' ...

# ===== Stage 2: Open file =====
IMM a 0x00          # a = filename pointer
SYS 0x4 a           # open("/flag") → fd in register a

# ===== Stage 3: Preserve FD on stack =====
STK NONE a          # PUSH fd onto VM stack

# ===== Stage 4: Prepare READ arguments =====
IMM a 0x00          # a = buffer address
IMM b 0x40          # b = read size (64 bytes)
STK c NONE          # POP fd from stack into register c

# ===== Stage 5: Read flag into memory =====
SYS 0x8 c           # read(fd, buffer, size)

# ===== Stage 6: Write to stdout =====
IMM a 0x01          # a = stdout fd
IMM b 0x00          # b = buffer address
IMM c 0x40          # c = size
SYS 0x1 a           # write(stdout, buffer, size)
```

**Key Techniques**:
1. **Immediate State Preservation**: Push critical values to stack immediately after generation
2. **Register Recycling**: Reuse registers once values are safely stored
3. **Careful Ordering**: Sequence operations to minimize register pressure

### 4.3 Constraints That Made This Challenging

1. **Limited Register File**: Only 4-7 usable registers depending on the challenge
2. **No Register Spilling**: Unlike x86, no automatic stack spills—manual management required
3. **Opcode Randomization**: Can't reuse payloads; must reassemble for each variant
4. **Syscall ABI Variations**: Argument register mappings differ between syscalls
5. **No Debugging Interface**: Can't attach debugger to VM internals; must rely on oracle or crash analysis

---

## Educational Takeaways

This challenge sharpened several critical cybersecurity skills:

### 1. **Emulator Security Model Understanding**

**Lesson**: Emulators are just programs—their interfaces (syscalls, I/O) can leak internal state.

The exit code oracle demonstrates that **side channels exist even in virtualized environments**. This applies to:
- JavaScript VM implementations (timing attacks)
- Cloud hypervisors (cache-based leaks)
- Sandboxed environments (resource exhaustion signals)

### 2. **Systematic ISA Reconstruction**

**Lesson**: Unknown instruction sets can be mapped through trial, error, and automation.

Skills developed:
- Identifying instruction format patterns through static analysis
- Correlating bytecode with semantic behavior via dynamic tracing
- Building oracles to accelerate discovery
- Automating hypothesis testing at scale

### 3. **Tool-Assisted Exploitation**

**Lesson**: Complex exploitation requires custom tooling—manual hex-editing doesn't scale.

Workflow:
1. **Identify patterns** (instruction format, syscall ABI)
2. **Abstract patterns** (layout maps, opcode tables)
3. **Build generators** (assembler for payloads)
4. **Verify outputs** (disassembler/interpreter for debugging)

This mirrors real-world exploit development, where tools like `pwntools`, `Metasploit`, and custom fuzzers are essential.

### 4. **Constraint-Based Problem Solving**

**Lesson**: Limited resources (registers, stack) force creative solutions.

The stack pivot technique demonstrates:
- **Resource management** under scarcity
- **State machine design** for multi-stage operations
- **Dependency analysis** to determine ordering constraints

These skills transfer directly to:
- Shellcode development (size-limited payloads)
- ROP chain construction (gadget constraints)
- Embedded systems exploitation (memory limitations)

### 5. **Vulnerability Research Mindset**

**Lesson**: Every interface is a potential attack surface—even seemingly benign features.

The exit syscall seemed innocuous but became the **linchpin** of the entire exploit chain. This reinforces:
- **Exhaustive analysis** of all program interfaces
- **Threat modeling** for unintended information flows
- **Creative abuse** of legitimate functionality

---

## Conclusion

Breaking the Yan85 emulator required the full spectrum of reverse engineering skills:
- **Static analysis** to understand architecture and identify candidate value sets
- **Creative problem-solving** to work around SUID debugging restrictions
- **Vulnerability research** to identify exploitable information disclosure
- **Tool development** to automate exploitation workflows
- **Constraint-based thinking** to overcome limited register resources

The exit code oracle transformed an opaque black box into a transparent system, demonstrating that **systematic methodology beats brute force**. By constraining the search space through static analysis (8 opcodes × 7 registers × 6 layouts = 336 attempts vs. 393,216 blind attempts), efficiency improved by ~1000x.

The custom assembler/disassembler proved that **automation is non-negotiable** for modern exploitation—manual hex-editing cannot scale to complex multi-stage payloads.

Most importantly, this challenge reinforced that **every program has an attack surface**—even the most abstract, virtualized environments leak information through their interfaces. The key is knowing where to look and how to systematically explore constrained possibility spaces.

---

**Author**: [Youssef Hasan]  
**Date**: January 2026  
**Challenge**: pwn.college - Yan85 Series (yansanity-hard)  
**Tools**: Ghidra 10.x, GDB, Python 3.x, pwntools

