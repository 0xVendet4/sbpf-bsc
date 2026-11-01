; Hello world: sol_log_ com string em rodata (região do programa)
    lddw r1, msg
    mov64 r2, 19
    call sol_log_
    mov64 r0, 0
    exit
msg:
    .ascii "Hello from sBPF/BSC"
