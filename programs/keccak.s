; keccak256 dos primeiros N bytes do input via syscall (keccak nativo da EVM).
; input: [u64 N][N bytes][32 bytes de saída]
    mov64 r6, r1
    ldxdw r7, [r6+0]
    ; monta slice {ptr, len} na pilha
    mov64 r2, r6
    add64 r2, 8
    stxdw [r10-16], r2
    stxdw [r10-8], r7
    mov64 r1, r10
    sub64 r1, 16
    mov64 r2, 1
    mov64 r3, r6
    add64 r3, 8
    add64 r3, r7            ; saída logo após os dados
    call sol_keccak256
    mov64 r0, 0
    exit
