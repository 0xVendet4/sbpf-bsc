; MDC de Euclides (mod por registrador; o zero é tratado antes).
; input: [u64 a][u64 b] -> r0
    ldxdw r0, [r1+0]
    ldxdw r2, [r1+8]
loop:
    jeq r2, 0, done
    mov64 r3, r0
    mod64 r3, r2
    mov64 r0, r2
    mov64 r2, r3
    ja loop
done:
    exit
