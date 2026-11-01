; máximo (sem sinal) de 8 valores u64.
; input: [u64 x 8] -> r0
    ldxdw r0, [r1+0]
    ldxdw r2, [r1+8]
    jge r0, r2, s1
    mov64 r0, r2
s1: ldxdw r2, [r1+16]
    jge r0, r2, s2
    mov64 r0, r2
s2: ldxdw r2, [r1+24]
    jge r0, r2, s3
    mov64 r0, r2
s3: ldxdw r2, [r1+32]
    jge r0, r2, s4
    mov64 r0, r2
s4: ldxdw r2, [r1+40]
    jge r0, r2, s5
    mov64 r0, r2
s5: ldxdw r2, [r1+48]
    jge r0, r2, s6
    mov64 r0, r2
s6: ldxdw r2, [r1+56]
    jge r0, r2, s7
    mov64 r0, r2
s7: exit
