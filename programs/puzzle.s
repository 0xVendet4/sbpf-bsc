; Puzzle de mineração do token POE.
; input: [s0 s1 s2 s3 : 4 x u64 (seed)][u64 nonce][u64 target]
; Mistura ARX/multiplicação por 32 rodadas; retorna 0 se hash < target.
    ldxdw r2, [r1+0]
    ldxdw r3, [r1+8]
    ldxdw r4, [r1+16]
    ldxdw r5, [r1+24]
    ldxdw r6, [r1+32]       ; nonce
    ldxdw r7, [r1+40]       ; target
    xor64 r2, r6
    mov64 r8, 32            ; rodadas
    lddw r9, 0x9E3779B97F4A7C15
round:
    xor64 r2, r3
    mul64 r2, r9
    mov64 r0, r2
    rsh64 r0, 29
    xor64 r2, r0
    add64 r3, r4
    xor64 r4, r5
    lsh64 r4, 7
    add64 r5, r2
    sub64 r8, 1
    jne r8, 0, round
    mov64 r0, r2
    xor64 r0, r5
    jlt r0, r7, ok
    mov64 r0, 1
    exit
ok:
    mov64 r0, 0
    exit
