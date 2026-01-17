#!/usr/bin/env python3
import sys
import os
import random
import string
import subprocess

def random_section_name(length=8):
    chars = string.ascii_lowercase + string.digits
    return '.' + ''.join(random.choice(chars) for _ in range(length))

def scrub_elf_sections(binary_path):
    try:
        import lief
    except ImportError:
        print("[!] lief not installed, attempting objcopy method")
        return scrub_elf_objcopy(binary_path)
    
    binary = lief.parse(binary_path)
    if binary is None:
        print(f"[!] Failed to parse {binary_path}")
        return False
    
    section_map = {}
    for section in binary.sections:
        if section.name in ['.text', '.data', '.rodata', '.bss', '.init', '.fini']:
            new_name = random_section_name()
            section_map[section.name] = new_name
            print(f"[*] Renaming {section.name} -> {new_name}")
            section.name = new_name
    
    output_path = binary_path + ".scrubbed"
    binary.write(output_path)
    os.replace(output_path, binary_path)
    print(f"[+] Scrubbed sections in {binary_path}")
    return True

def scrub_elf_objcopy(binary_path):
    sections_to_rename = ['.text', '.data', '.rodata', '.bss', '.init', '.fini']
    
    for section in sections_to_rename:
        new_name = random_section_name()
        cmd = ['objcopy', '--rename-section', f'{section}={new_name}', binary_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[*] Renamed {section} -> {new_name}")
            else:
                print(f"[!] Failed to rename {section}: {result.stderr}")
        except FileNotFoundError:
            print("[!] objcopy not found, section scrubbing skipped")
            return False
    
    print(f"[+] Scrubbed sections in {binary_path}")
    return True

def scrub_pe_sections(binary_path):
    try:
        import lief
    except ImportError:
        print("[!] lief not installed, PE section scrubbing skipped")
        return False
    
    binary = lief.parse(binary_path)
    if binary is None:
        print(f"[!] Failed to parse {binary_path}")
        return False
    
    section_map = {}
    for section in binary.sections:
        if section.name in ['.text', '.data', '.rdata', '.bss']:
            new_name = random_section_name()[:8]
            section_map[section.name] = new_name
            print(f"[*] Renaming {section.name} -> {new_name}")
            section.name = new_name
    
    output_path = binary_path + ".scrubbed"
    binary.write(output_path)
    os.replace(output_path, binary_path)
    print(f"[+] Scrubbed sections in {binary_path}")
    return True

def scrub_macho_sections(binary_path):
    try:
        import lief
    except ImportError:
        print("[!] lief not installed, Mach-O section scrubbing skipped")
        return False
    
    binary = lief.parse(binary_path)
    if binary is None:
        print(f"[!] Failed to parse {binary_path}")
        return False
    
    for segment in binary.segments:
        for section in segment.sections:
            if section.name in ['__text', '__data', '__const', '__bss']:
                new_name = random_section_name()[:16]
                print(f"[*] Renaming {section.name} -> {new_name}")
                section.name = new_name
    
    output_path = binary_path + ".scrubbed"
    binary.write(output_path)
    os.replace(output_path, binary_path)
    print(f"[+] Scrubbed sections in {binary_path}")
    return True

def detect_format(binary_path):
    with open(binary_path, 'rb') as f:
        magic = f.read(4)
        if magic[:4] == b'\x7fELF':
            return 'ELF'
        elif magic[:2] == b'MZ':
            return 'PE'
        elif magic[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                           b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            return 'MACHO'
    return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
        print(f"[!] File not found: {binary_path}")
        sys.exit(1)
    
    fmt = detect_format(binary_path)
    if fmt is None:
        print(f"[!] Unknown binary format: {binary_path}")
        sys.exit(1)
    
    print(f"[*] Detected {fmt} format")
    
    success = False
    if fmt == 'ELF':
        success = scrub_elf_sections(binary_path)
    elif fmt == 'PE':
        success = scrub_pe_sections(binary_path)
    elif fmt == 'MACHO':
        success = scrub_macho_sections(binary_path)
    
    if success:
        subprocess.run(['strip', '-s', binary_path], capture_output=True)
        print(f"[+] Stripped symbols from {binary_path}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
