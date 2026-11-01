; popcount: número de bits 1.
; input: [u64 x] -> r0
    ldxdw r1, [r1+0]
    mov64 r0, 0
loop:
    jeq r1, 0, done
    mov64 r2, r1
    and64 r2, 1
    add64 r0, r2
    rsh64 r1, 1
    ja loop
done:
    exit
