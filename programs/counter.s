; Contador com estado persistente (conta de dados de 8 bytes).
; input: [u64 8][u64 counter][u64 ix_len][ix: u64 delta opcional]...
    ldxdw r2, [r1+8]        ; valor atual
    ldxdw r3, [r1+16]       ; tamanho do instruction data
    mov64 r4, 1
    jeq r3, 0, apply
    ldxdw r4, [r1+24]       ; delta
apply:
    add64 r2, r4
    lddw r5, 1000000
    jgt r2, r5, fail        ; limite: falha (tx reverte) acima de 1e6
    stxdw [r1+8], r2        ; grava de volta na conta
    mov64 r1, r2
    mov64 r2, r4
    mov64 r3, 0
    mov64 r4, 0
    mov64 r5, 0
    call sol_log_64_
    mov64 r0, 0
    exit
fail:
    mov64 r0, 42
    exit
