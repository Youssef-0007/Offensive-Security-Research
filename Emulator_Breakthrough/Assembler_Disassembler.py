#!/usr/bin/env python3

import argparse
import base64
from pwn import info

#--------------------- the mapings ---------------------- #

# --------- vm opcode ---------#
vm_op = {
        "IMM": 0x8,
        "ADD": 0x1,
        "STK": 0x2,
        "STM": 0x20,
        "LDM": 0x4,
        "CMP": 0x10,
        "JMP": 0x40,
        "SYS": 0x80
}

# -------- Syscalls ----------#
vm_syscall = {
        "open": 0x4,
        "read_code": 0x20,
        "read_mem": 0x8,
        "write": 0x1,
        "sleep": 0x2,
        "exit": 0x10
}

# -------- jump conditions mapping ----------#
vm_jmp = {
    "L": 0x2,
    "G": 0x8,
    "E": 0x4,
    "N": 0x1,
    "Z": 0x10,
    "*": 0x0
}

# -------- register mapping for disassembler ----------#
vm_reg = {
    "a": 0x2,
    "b": 0x20,
    "c": 0x1,
    "d": 0x8,
    "s": 0x40,
    "i": 0x4,
    "f": 0x10,
    "NONE": 0x0
}

# ---------- Order mapping ------------- #    
# Map the layout string to index positions
ORDER_MAPS = {
    "a1_a2_op": {"arg1": 0, "arg2": 1, "opcode": 2},
    "a1_op_a2": {"arg1": 0, "opcode": 1, "arg2": 2},
    "a2_op_a1": {"arg2": 0, "opcode": 1, "arg1": 2},
    "a2_a1_op": {"arg2": 0, "arg1": 1, "opcode": 2},
    "op_a1_a2": {"opcode": 0, "arg1": 1, "arg2": 2},
    "op_a2_a1": {"opcode": 0, "arg2": 1, "arg1": 2}
}

# Change this single line to match the current challenge
# Available: "a1_a2_op", "a1_op_a2", "a2_op_a1", "a2_a1_op", "op_a1_a2", "op_a2_a1"
# ========= MODIFY ========= #
CURRENT_ORDER = "a2_a1_op"

def parse_args():
    parser = argparse.ArgumentParser(description="YAN85 VM assembler & disassembler")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--disassemble", action='store_true', help="disassemble the yan85 opcode")
    group.add_argument("-a", "--assemble", action='store_true', help="assemble the yan85 instruction")
    group.add_argument("-b64", "--base64", action='store_true', help="base64 encode the output")
    parser.add_argument("file", help="file to process")

    args = parser.parse_args()
    
    if args.file is None:
        parser.print_help()
        exit()
    
    return args

def reg_lookup(val):
    for k, v in vm_reg.items():
        if val == v:
            return k
    assert False, f"Unknown register value: 0x{val:02x}"


class vm_registers:
    def __init__(self, a: int, b: int, c: int, d: int, s: int, i: int, f: int):
        self.a_hex = a  # general purpose register
        self.b_hex = b  # general purpose register
        self.c_hex = c  # general purpose register
        self.d_hex = d  # general purpose register
        self.s_hex = s  # stack pointer register
        self.i_hex = i  # instruction register
        self.f_hex = f  # flag register
        
        self.register_map = {self.a_hex:'a', self.b_hex:'b', self.c_hex:'c', 
                           self.d_hex:'d', self.s_hex:'s', self.i_hex:'i', self.f_hex:'f'}
        
        self.register: dict[int, int] = {self.a_hex:0, self.b_hex:0, self.c_hex:0, 
                                       self.d_hex:0, self.s_hex:0, self.i_hex:0, self.f_hex:0}
    
    def write_register(self, register: int, value: int) -> None:
        self.register[register] = value & 0xFF
    
    def read_register(self, register: int) -> int:
        return self.register[register]
    
    def get_register_name(self, register: int) -> str:
        return self.register_map.get(register, f"UNK_{register:02x}")

class vm_memory:
   def __init__(self,vm_mem_size: int) -> None:
      self.vm_memory: list[int] = [0] * vm_mem_size 

   def write_memory(self,position: int,data: int) -> None:
      self.vm_memory[position] = data

   def read_memory(self,position: int)->int:
      return self.vm_memory[position]
   
   def read_entire_vm_memory(self) -> list[int]:
      return self.vm_memory

class vm_stack:
    def __init__(self, registers: vm_registers, memory: vm_memory):
        #self.stack: list[int] = [0] * size
        self.memory = memory    # stack usually lives in main memory
        self.registers = registers
    
    def push_stack(self, value: int) -> None:
        # 1. Get current SP and increment it (matching S = S + 1)
        sp = self.registers.read_register(vm_reg['s'])
        new_sp = (sp + 1) & 0xFF
        
        # 2. Write the value to the NEW address
        self.memory.write_memory(new_sp, value)
        
        # 3. Update the register with the new pointer
        self.registers.write_register(vm_reg['s'], new_sp)
    
    def pop_stack(self) -> int:
        # 1. Read value at CURRENT SP
        sp = self.registers.read_register(vm_reg['s'])
        value = self.memory.read_memory(sp)
        
        # 2. Decrement SP (matching S = S - 1)
        new_sp = (sp - 1) & 0xFF
        self.registers.write_register(vm_reg['s'], new_sp)
        
        return value

class interpret_instructions:
    def __init__(self, registers: vm_registers, stack: vm_stack, memory: vm_memory):
        self.registers = registers
        self.stack = stack
        self.memory = memory
    
    def imm(self, arg1: int, arg2: int) -> None:
        """Interpret the immediate load instruction by loading value to register"""
        self.registers.write_register(arg1, arg2)
        print(f"  [EXEC] Loaded 0x{arg2:02x} into register {self.registers.get_register_name(arg1)}")

    def add(self, arg1: int, arg2: int) -> None:
        var1 = self.registers.read_register(arg1)
        var2 = self.registers.read_register(arg2)
        result = var1 + var2
        self.registers.write_register(arg1, result)
        print(f"  [EXEC] {self.registers.get_register_name(arg1)} = {var1} + {var2} = {result}")

    def stk(self, arg1: int, arg2: int, stk_num: int) -> None:
        if stk_num == 0:
            # pop from stak to the arg1 -> register
            self.registers.write_register(arg1, self.stack.pop_stack())
        elif stk_num == 1:
            # push to stak the arg2 -> register
            var1 = self.registers.read_register(arg2)
            self.stack.push_stack(var1)
        elif stk_num == 2:
            # push then pop
            var1 = self.registers.read_register(arg2)
            self.stack.push_stack(var1)
            self.registers.write_register(arg1, self.stack.pop_stack())
    
    
    def stm(self, arg1: int, arg2: int) -> None:
        # read the value of the first register (arg1)
        dest = self.registers.read_register(arg1)
        # read the value of the second register (arg2)
        value = self.registers.read_register(arg2)
        # *dest = value ==> *arg1 = arg2
        self.memory.write_memory(dest, value)
    
    
    def ldm(self, arg1: int, arg2: int)-> None:
        # read from register for arg2
        var1 = self.registers.read_register(arg2)
        # read from memory for the register value
        var1 = self.memory.read_memory(var1 & 0xFF)
        # write to the register of arg1, the extracted value
        self.registers.write_register(arg1, var1)
    
    def cmp(self, arg1: int, arg2: int) -> None:
        # first clear the flag register
        # first clear the flag register
        self.registers.write_register(vm_reg['f'], 0)
        # read the value of the two registers arguments
        v1 = self.registers.read_register(arg1)
        v2 = self.registers.read_register(arg2)
        # this compare conditions reults (the value sat to flag register is changable between the yan85 levels [not fixed])
        f_reg = 0
        if v1 > v2:  f_reg |= 0x10 # G
        if v1 < v2:  f_reg |= 0x01 # L
        if v1 == v2: f_reg |= 0x04 # E
        if v1 != v2: f_reg |= 0x08 # N
        if v1 == 0 and v2 == 0: f_reg |= 0x02 # Z
        
        self.registers.write_register(vm_reg['f'], f_reg)
    
    def jmp(self, arg1: int, arg2: int, cond_str: str) -> None:
        # first read the flag register 
        f_reg = self.registers.read_register(vm_reg['f'])
        # If condition is '*' (arg1=0) or the flag bit matches the condition
        if cond_str == 0 or (f_reg & arg1):
            print("... TAKEN")
            target_ip = self.registers.read_register(arg2)
            # We write to 'i', and our loop in disassemble_yan_85 reads this next!
            self.registers.write_register(vm_reg['i'], target_ip)
        else:
            print("... NOT TAKEN")
    
    def sys(self, syscall: int, reg: int) -> None:
        
        
        if syscall == vm_syscall["open"]:
            # open syscall
            print(f"[s]... open")
        elif syscall == vm_syscall["read_code"]:
            # read code syscall
            print(f"[s] ... read_code")
        elif syscall == vm_syscall["read_mem"]:
            # read memory syscall
            print(f"[s] ... read_memory")
            user_input = input("ENTER FLAG: ")
            # In Yan85, 'read' usually puts the length of input in a register
            # and stores the actual bytes in a memory buffer.
            """
            for idx, char in enumerate(user_input):
                self.memory.write_memory(buffer_start + idx, ord(char))
            self.registers.write_register(target_reg, len(user_input))
            """
        elif syscall == vm_syscall["write"]:
            # write syscall
            print(f"[s] ... write")
        elif syscall == vm_syscall["sleep"]:
            # sleep syscall
            print(f"[s] ... sleep")
        elif syscall == vm_syscall["exit"]:
            # exit syscall
            print(f"[s] ... exit")
            exit(1)
            
    
class disassemble_yan_85:
    def __init__(self, op_code: bytes, registers: vm_registers, interpreter: interpret_instructions):
        self.op_code = op_code
        self.registers = registers
        self.interpreter = interpreter
    
    def reg(self, val: int) -> str:
        """Convert register byte value to name"""
        return reg_lookup(val)
    
    def interpret_loop(self):
        """Main disassembly and interpretation loop"""
        if len(self.op_code) % 3 != 0:
            print(f"[WARNING] Bytecode length {len(self.op_code)} not divisible by 3")
        
        # Reset instruction pointer
        self.registers.write_register(self.registers.i_hex, 0)
        
        # Pick the current instruction order
        layout = ORDER_MAPS[CURRENT_ORDER]

        # Use the VM's internal register as the master pointer
        while True:
            # 1. Get current IP and convert to byte offset
            curr_ip = self.registers.read_register(self.registers.i_hex)
            offset = curr_ip * 3
            
            if offset + 3 > len(self.op_code):
                break

            # 2. Fetch the instruction
            chunk = self.op_code[offset:offset+3]
            # DYNAMIC UNPACKING based on the selected order
            op = chunk[layout["opcode"]]
            arg1 = chunk[layout["arg1"]]
            arg2 = chunk[layout["arg2"]] 

            # 3. Increment the IP register BEFORE execution
            # If a JMP occurs, the execution phase will overwrite this.
            self.registers.write_register(self.registers.i_hex, curr_ip + 1)
            
            # Find opcode name
            op_name = None
            for k, v in vm_op.items():
                if op == v:
                    op_name = k
                    break
            
            if op_name is None:
                print(f"{offset:04x}: DB 0x{op:02x} 0x{arg1:02x} 0x{arg2:02x}  # Unknown opcode")
                continue
            
            # Display register state
            reg_a = self.registers.read_register(self.registers.a_hex)
            reg_b = self.registers.read_register(self.registers.b_hex)
            reg_c = self.registers.read_register(self.registers.c_hex)
            reg_d = self.registers.read_register(self.registers.d_hex)
            reg_s = self.registers.read_register(self.registers.s_hex)
            reg_i = self.registers.read_register(self.registers.i_hex)
            reg_f = self.registers.read_register(self.registers.f_hex)
            
            print(f"{offset:04x}: [A=0x{reg_a:02x} B=0x{reg_b:02x} C=0x{reg_c:02x} D=0x{reg_d:02x} S=0x{reg_s:02x} I=0x{reg_i:02x} F=0x{reg_f:02x}]")
            
            # Process each instruction type
            if op_name == "IMM":
                reg_name = self.reg(arg1)
                print(f"      {op_name} {reg_name} 0x{arg2:02x}")
                # Execute the instruction
                self.interpreter.imm(arg1, arg2)
                
            elif op_name == "ADD":
                reg1_name = self.reg(arg1)
                reg2_name = self.reg(arg2)
                print(f"      {op_name} {reg1_name} {reg2_name}")
                # Execute the instruction
                self.interpreter.add(arg1, arg2)
                
            elif op_name == "STK":
                reg1_name = self.reg(arg1)
                reg2_name = self.reg(arg2)
                # stk operations 0 -> pop, 1 -> push, 2 -> pop&push
                stk_operation = 0
                if arg1 != vm_reg['NONE'] and arg2 != vm_reg['NONE']:
                    print(f"      {op_name} {reg1_name} {reg2_name}")
                    print(f"        ... pushing {reg2_name}")
                    print(f"        ... popping {reg1_name}")
                    stk_operation = 2
                elif arg1 != vm_reg['NONE']:
                    print(f"      {op_name} {reg1_name} NONE")
                    print(f"        ... popping {reg1_name}")
                    stk_operation = 0
                elif arg2 != vm_reg['NONE']:
                    print(f"      {op_name} NONE {reg2_name}")
                    print(f"        ... pushing {reg2_name}")
                    stk_operation = 1
                self.interpreter.stk(arg1, arg2, stk_operation)
            
            elif op_name == "STM":
                reg1_name = self.reg(arg1)
                reg2_name = self.reg(arg2)
                print(f"      {op_name} *{reg1_name} = {reg2_name}")
                self.interpreter.stm(arg1, arg2)
                
            elif op_name == "LDM":
                reg1_name = self.reg(arg1)
                reg2_name = self.reg(arg2)
                print(f"      {op_name} {reg1_name} = *{reg2_name}")
                self.interpreter.ldm(arg1, arg2)
                
            elif op_name == "CMP":
                reg1_name = self.reg(arg1)
                reg2_name = self.reg(arg2)
                print(f"      {op_name} {reg1_name} {reg2_name}")
                self.interpreter.cmp(arg1, arg2)
                
            elif op_name == "JMP":
                cond_byte = arg1
                target_reg = self.reg(arg2)
                
                # Decode condition flags
                cond_names = []
                for cond_name, cond_mask in vm_jmp.items():
                    if cond_byte & cond_mask:
                        cond_names.append(cond_name)
                
                cond_str = "|".join(cond_names) if cond_names else "0x{cond_byte:02x}"
                if cond_byte == 0:
                    cond_str = "*"  # Unconditional
                    
                print(f"      {op_name} {cond_str} {target_reg}")
                self.interpreter.jmp(arg1, arg2, cond_str)
                
            elif op_name == "SYS":
                syscall_byte = arg1
                ret_reg = self.reg(arg2)
                
                # Find syscall name
                syscall_name = None
                for k, v in vm_syscall.items():
                    if syscall_byte == v:
                        syscall_name = k
                        break
                
                if syscall_name:
                    print(f"      {op_name} {syscall_byte} {ret_reg}")
                    print(f"      .... {syscall_name}")
                    self.interpreter.sys(arg1, ret_reg)
                else:
                    print(f"      {op_name} 0x{syscall_byte:02x} {ret_reg}")
            
class assemble_yan85:
    def __init__(self, op_code: str):
        self.op_code = op_code
    
    def interpret_loop(self) -> bytes:
        payload = b""
        insts = self.op_code.split("\n")
        for inst in insts:
            # Skip empty lines to avoid returning None
            if not inst.strip():
                continue
            
            res = self.assemble(inst)
            if res is not None:
                payload += res
            else:
                # This helps you debug which line is breaking your assembler
                print(f"[!] Warning: Assembler failed on line: {inst}")
        
        return payload

    
    def pack_layout(self, v_op, v_a1, v_a2):
        """Packs values into the correct order based on CHALLENGE_LAYOUT"""
        # Pick the current instruction order
        layout = ORDER_MAPS[CURRENT_ORDER]
        res = [0, 0, 0]
        res[layout["opcode"]] = v_op
        res[layout["arg1"]] = v_a1
        res[layout["arg2"]] = v_a2
        return bytes(res)
    
    def assemble(self, instruction: str) -> bytes:
        # 1. Strip comments and unwanted symbols (=, *)
        # We replace them with spaces so .split() handles the gaps
        clean_inst = instruction.split('#')[0]
        for char in "=*":
            clean_inst = clean_inst.replace(char, " ")
        
        parts = clean_inst.split()
        if not parts:
            return b""
            
        op = parts[0]
        # After stripping '*', 'STM *a = b' becomes ['STM', 'a', 'b']
        arg1 = parts[1] if len(parts) > 1 else "NONE"
        arg2 = parts[2] if len(parts) > 2 else "NONE"

        if op not in vm_op:
            return b""

        v = vm_op[op]

        # 2. Advanced Parsing for the 3-byte format
        for k, v in vm_op.items():
            if op == k:
                if k == "IMM":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_reg.items():
                        if arg1 == k1:
                            hex_str = arg2.replace("0x", "")
                            if len(hex_str) % 2 != 0:
                                hex_str = "0" + hex_str
                            
                            # CONVERT TO INTEGER instead of bytes.fromhex
                            v2_int = int(hex_str, 16) 
                            
                            return self.pack_layout(v, v1, v2_int)
                elif k == "ADD":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_reg.items():
                        if arg1 == k1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2_int)
                elif k == "STK":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_reg.items():
                        if arg1 == k1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2)
                elif k == "STM":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_reg.items():
                        if arg1 == k1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2)
                elif k == "LDM":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_reg.items():
                        if arg1 == k1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2)
                elif k == "CMP":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_reg.items():
                        if arg1 == k1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2)
                elif k == "JMP":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_jmp.items():
                        if arg1 == k1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2)
                elif k == "SYS":
                    info(f"{op} {arg1} {arg2}")
                    for k1, v1 in vm_syscall.items():
                        if int(arg1, 16) == v1:
                            for k2, v2 in vm_reg.items():
                                if arg2 == k2:
                                    return self.pack_layout(v, v1, v2)
    
if __name__ == "__main__":
    args = parse_args()
    
    if args.disassemble:
        # Create register instance with correct values
        # ====== MODIFY THIS TO SUIT REGISTER MAPPING ==========
        reg_class = vm_registers(0x2, 0x40, 0x20, 0x4, 0x8, 0x10, 0x1)
        # Create and initialize the virtual memory, virtual stack, and set up instructions interpreter 
        virtual_mem = vm_memory(2000)
        virtual_stack = vm_stack(reg_class, virtual_mem)
        interpreter = interpret_instructions(reg_class, virtual_stack, virtual_mem)
        # open the op_bytes file 
        with open(args.file, "rb") as f:
            vm_code = f.read()
            disassembler = disassemble_yan_85(vm_code, reg_class, interpreter)
            disassembler.interpret_loop()
    elif args.assemble: 
        with open(args.file, "r") as f:
            ins = f.read()
            # set-up the assembler
            assembler = assemble_yan85(ins)
            assm_bytes = assembler.interpret_loop()

            with open("op_bytes", "wb") as f:
                    f.write(assm_bytes)
            
            if args.base64:
                info(f"base64: {base64.b64encode(assm_bytes)}")
            else:
                info(f"payload: {assm_bytes}")