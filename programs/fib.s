; fib(n) iterativo, aritmética de 64 bits com wraparound (igual à VM).
; input: [u64 n] -> r0 = fib(n)
    ldxdw r1, [r1+0]
    mov64 r0, 0
    mov64 r2, 1
loop:
    jeq r1, 0, done
    mov64 r3, r0
    add64 r3, r2
    mov64 r0, r2
    mov64 r2, r3
    sub64 r1, 1
    ja loop
done:
    exit
