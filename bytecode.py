import pefile

pe = pefile.PE("picshellcode.exe")

text_section = next(
    (s for s in pe.sections if s.Name.decode().strip('\x00') == '.text'),
    None
)

if not text_section:
    print("Секция .text не найдена")
else:
    text_bytes = text_section.get_data()
    
    with open("shellcode.txt", "w") as f:
        c_array = ', '.join(f'0x{b:02x}' for b in text_bytes)
        f.write(f'unsigned char payload[] = {{ {c_array} }};\n')
    
    print(f"[+] Извлечено {len(text_bytes)} байт")
    print("[+] Сохранено в shellcode.txt")