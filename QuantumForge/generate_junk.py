#!/usr/bin/env python3
import random
import sys

def generate_junk_asm(num_instructions=50):
    nop_variants = [
        "nop",
        "xchg %%rax, %%rax",
        "lea 0(%%rsi), %%rsi",
        "mov %%rax, %%rax",
        "mov %%rbx, %%rbx",
        "xor %%rcx, %%rcx\\n    xor %%rcx, %%rcx",
        "add $0, %%rax",
        "sub $0, %%rbx",
        "shl $0, %%rcx",
        "test %%rax, %%rax",
        "cmp %%rax, %%rax",
        "push %%rax\\n    pop %%rax",
        "push %%rbx\\n    pop %%rbx",
        "inc %%rax\\n    dec %%rax",
        "dec %%rbx\\n    inc %%rbx"
    ]
    
    instructions = []
    for _ in range(num_instructions):
        instructions.append(random.choice(nop_variants))
    
    return "\\n    ".join(instructions)

def generate_junk_header():
    junk_asm = generate_junk_asm(random.randint(30, 80))
    
    header = f"""#ifndef JUNK_H
#define JUNK_H

#define JUNK_ASM __asm__ __volatile__( \\
    "{junk_asm}" \\
    ::: "rax", "rbx", "rcx", "rdx", "memory" \\
)

static inline void junk_func_{random.randint(1000, 9999)}(void) {{
    volatile int x = {random.randint(100, 999)};
    volatile int y = {random.randint(100, 999)};
    x = x ^ y;
    y = y + x;
    x = x - y;
    if (x > y) {{
        x = x * {random.randint(2, 5)};
    }} else {{
        y = y / {random.randint(2, 5)};
    }}
}}

static inline unsigned int junk_hash_{random.randint(1000, 9999)}(unsigned int seed) {{
    seed ^= seed << {random.randint(10, 15)};
    seed ^= seed >> {random.randint(5, 12)};
    seed ^= seed << {random.randint(3, 8)};
    return seed;
}}

#define JUNK_CALL junk_func_{random.randint(1000, 9999)}()

#endif
"""
    return header

if __name__ == "__main__":
    output_file = "junk.h"
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    
    with open(output_file, "w") as f:
        f.write(generate_junk_header())
    
    print(f"[+] Generated {output_file} with polymorphic junk code")
