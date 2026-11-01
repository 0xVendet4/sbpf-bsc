; fib(n) recursivo usando call interno (frames de pilha + r6..r9 preservados)
; input: [u64 n]  ->  r0 = fib(n)
    ldxdw r1, [r1+0]
    call fib
    exit
fib:                    ; r1 = n -> r0 = fib(n). Usa iteração após profundidade 1
    mov64 r6, r1
    jgt r6, 1, rec
    mov64 r0, r6
    exit
rec:
    ; fib(n) = fib_iter(n-1) + fib_iter(n-2)
    mov64 r1, r6
    sub64 r1, 1
    call iter
    mov64 r7, r0
    mov64 r1, r6
    sub64 r1, 2
    call iter
    add64 r0, r7
    exit
iter:                   ; r1 = n -> r0 = fib(n), iterativo
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
