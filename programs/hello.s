; "Hello" sem syscalls: escreve os bytes na pilha e lê de volta como u64.
; input: nenhum -> r0 = 0x6f6c6c6548 ("Hello" little-endian)
    stb [r10-8], 0x48         ; H
    stb [r10-7], 0x65         ; e
    stb [r10-6], 0x6c         ; l
    stb [r10-5], 0x6c         ; l
    stb [r10-4], 0x6f         ; o
    ldxdw r0, [r10-8]
    exit
