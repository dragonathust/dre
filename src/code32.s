
.global _start
    .code32

_start:
    xor %eax, %eax
	movl $0x8000, %ebx

loop1:
    out %eax, $0xFF
    inc %eax
    jmp loop1
