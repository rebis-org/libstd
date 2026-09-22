#ifdef __APPLE__
#define SYM(x) _##x
#define HIDDEN(x) .private_extern x
#else
#define SYM(x) x
#define HIDDEN(x) .hidden x
#endif

# CRC-32 (reflected, poly 0xEDB88320) for x86_64: SSE4.2 scalar accumulation
# plus a PCLMULQDQ 4-way folding kernel. The folding constants and lane
# layout are the algorithm's, not the architecture's — they are byte-for-byte
# the ones the shipped aarch64 PMULL kernel uses, so bit-identity across
# arches is by construction, not by testing.

.text
.align 4
.globl SYM(stdk_crc32_x86_le)
HIDDEN(SYM(stdk_crc32_x86_le))
SYM(stdk_crc32_x86_le):
	mov	%edi, %eax
	test	%rdx, %rdx
	jz	3f
1:
	cmp	$8, %rdx
	jb	2f
	movq	(%rsi), %r8
	add	$8, %rsi
	sub	$8, %rdx
	crc32q	%r8, %rax
	jmp	1b
2:
	cmp	$4, %rdx
	jb	4f
	movl	(%rsi), %r8d
	add	$4, %rsi
	sub	$4, %rdx
	crc32l	%r8d, %eax
	jmp	2b
4:
	test	%rdx, %rdx
	jz	3f
	movzbl	(%rsi), %r8d
	add	$1, %rsi
	sub	$1, %rdx
	crc32b	%r8b, %eax
	jmp	4b
3:
	ret

/* Called only for len >= threshold. */
.align 4
.globl SYM(stdk_crc32_x86_le_pmull)
HIDDEN(SYM(stdk_crc32_x86_le_pmull))
SYM(stdk_crc32_x86_le_pmull):
	mov	%edi, %r9d

0:
	test	$0xf, %rsi
	jz	1f
	movzbl	(%rsi), %eax
	add	$1, %rsi
	sub	$1, %rdx
	crc32b	%al, %r9d
	test	%rdx, %rdx
	jnz	0b
	mov	%r9d, %eax
	ret

1:
	cmp	$64, %rdx
	jb	5f
	movdqu	(%rsi), %xmm0
	movdqu	16(%rsi), %xmm1
	movdqu	32(%rsi), %xmm2
	movdqu	48(%rsi), %xmm3
	movdqa	Lcrc32_k0(%rip), %xmm4
	movd	%r9d, %xmm5
	pxor	%xmm5, %xmm0
	add	$64, %rsi
	sub	$64, %rdx

2:
	cmp	$64, %rdx
	jb	3f
	movdqu	(%rsi), %xmm5
	movdqu	16(%rsi), %xmm6
	movdqu	32(%rsi), %xmm7
	movdqu	48(%rsi), %xmm8
	movdqa	%xmm0, %xmm13
	pclmulqdq	$0x00, %xmm4, %xmm13
	pclmulqdq	$0x11, %xmm4, %xmm0
	pxor	%xmm13, %xmm0
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm13
	pclmulqdq	$0x00, %xmm4, %xmm13
	pclmulqdq	$0x11, %xmm4, %xmm1
	pxor	%xmm13, %xmm1
	pxor	%xmm6, %xmm1
	movdqa	%xmm2, %xmm13
	pclmulqdq	$0x00, %xmm4, %xmm13
	pclmulqdq	$0x11, %xmm4, %xmm2
	pxor	%xmm13, %xmm2
	pxor	%xmm7, %xmm2
	movdqa	%xmm3, %xmm13
	pclmulqdq	$0x00, %xmm4, %xmm13
	pclmulqdq	$0x11, %xmm4, %xmm3
	pxor	%xmm13, %xmm3
	pxor	%xmm8, %xmm3
	add	$64, %rsi
	sub	$64, %rdx
	jmp	2b

3:
	movdqa	Lcrc32_k1(%rip), %xmm4
	movdqa	%xmm0, %xmm5
	pclmulqdq	$0x00, %xmm4, %xmm5
	pclmulqdq	$0x11, %xmm4, %xmm0
	pxor	%xmm5, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm2, %xmm5
	pclmulqdq	$0x00, %xmm4, %xmm5
	pclmulqdq	$0x11, %xmm4, %xmm2
	pxor	%xmm5, %xmm2
	pxor	%xmm3, %xmm2
	movdqa	Lcrc32_k2(%rip), %xmm4
	movdqa	%xmm0, %xmm5
	pclmulqdq	$0x00, %xmm4, %xmm5
	pclmulqdq	$0x11, %xmm4, %xmm0
	pxor	%xmm5, %xmm0
	pxor	%xmm2, %xmm0
	movq	%xmm0, %r8
	mov	$0, %eax
	crc32q	%r8, %rax
	psrldq	$8, %xmm0
	movq	%xmm0, %r8
	crc32q	%r8, %rax
	mov	%eax, %r9d

5:
	cmp	$16, %rdx
	jb	6f
	movdqu	(%rsi), %xmm0
	movd	%r9d, %xmm1
	pxor	%xmm1, %xmm0
	add	$16, %rsi
	sub	$16, %rdx
	movdqa	Lcrc32_k1(%rip), %xmm1
7:
	cmp	$16, %rdx
	jb	8f
	movdqu	(%rsi), %xmm2
	add	$16, %rsi
	sub	$16, %rdx
	movdqa	%xmm0, %xmm3
	pclmulqdq	$0x00, %xmm1, %xmm3
	pclmulqdq	$0x11, %xmm1, %xmm0
	pxor	%xmm3, %xmm0
	pxor	%xmm2, %xmm0
	jmp	7b
8:
	movq	%xmm0, %r8
	mov	$0, %eax
	crc32q	%r8, %rax
	psrldq	$8, %xmm0
	movq	%xmm0, %r8
	crc32q	%r8, %rax
	mov	%eax, %r9d

6:
	cmp	$8, %rdx
	jb	9f
	movq	(%rsi), %r8
	add	$8, %rsi
	sub	$8, %rdx
	crc32q	%r8, %r9
9:
	test	%rdx, %rdx
	jz	10f
	movzbl	(%rsi), %eax
	add	$1, %rsi
	sub	$1, %rdx
	crc32b	%al, %r9d
	jmp	9b
10:
	mov	%r9d, %eax
	ret

.align 4
Lcrc32_k0:
	.quad	0x000000008f352d95
	.quad	0x000000001d9513d7
Lcrc32_k1:
	.quad	0x00000000ae689191
	.quad	0x00000000ccaa009e
Lcrc32_k2:
	.quad	0x00000000f1da05aa
	.quad	0x0000000081256527
