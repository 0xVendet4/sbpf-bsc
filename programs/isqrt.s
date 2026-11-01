; isqrt: floor(sqrt(x)) bit a bit, sem overflow em 64 bits.
; input: [u64 x] -> r0
    ldxdw r1, [r1+0]          ; x
    mov64 r0, 0               ; resultado
    mov64 r2, 1
    lsh64 r2, 62              ; bit = 1 << 62
shrink:
    jle r2, r1, loop
    rsh64 r2, 2
    jne r2, 0, shrink
loop:
    jeq r2, 0, done
    mov64 r3, r0
    add64 r3, r2              ; res + bit
    jlt r1, r3, skip
    sub64 r1, r3              ; x -= res + bit
    rsh64 r0, 1
    add64 r0, r2              ; res = (res >> 1) + bit
    ja next
skip:
    rsh64 r0, 1
next:
    rsh64 r2, 2
    ja loop
done:
    exit
