exe = call_func.asm
shellcode:
        nasm -f bin $(exe) -o shellcode.bin ; hexdump -v -e '"\\" "x" /1 "%02x"' shellcode.bin
