#ifdef __APPLE__
#define SYM(x) _##x
#define HIDDEN(x) .private_extern x
#else
#define SYM(x) x
#define HIDDEN(x) .hidden x
#endif

.text
.arch_extension crc
.arch_extension crypto
.align 2
.globl SYM(stdk_crc32_le)
HIDDEN(SYM(stdk_crc32_le))
SYM(stdk_crc32_le):
	cbz	x2, 3f
1:
	cmp	x2, #8
	b.lo	2f
	ldr	x3, [x1], #8
	crc32x	w0, w0, x3
	sub	x2, x2, #8
	b	1b
2:
	cmp	x2, #4
	b.lo	4f
	ldr	w3, [x1], #4
	crc32w	w0, w0, w3
	sub	x2, x2, #4
	b	2b
4:
	cbz	x2, 3f
	ldrb	w3, [x1], #1
	crc32b	w0, w0, w3
	sub	x2, x2, #1
	b	4b
3:
	ret

/* PMULL/PMULL2 4x128-bit folding CRC32. Called only for len >= threshold. */
.align 2
.globl SYM(stdk_crc32_le_pmull)
HIDDEN(SYM(stdk_crc32_le_pmull))
SYM(stdk_crc32_le_pmull):
	mov	w9, w0

	/* Align to 16 bytes with crc32b. */
0:
	ands	x3, x1, #0xf
	b.eq	1f
	ldrb	w3, [x1], #1
	crc32b	w9, w9, w3
	sub	x2, x2, #1
	cbnz	x2, 0b
	b	9f

1:
	/* Main 64-byte PMULL folding loop. */
	cmp	x2, #64
	b.lo	5f
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x1, #32]
	movi	v4.2d, #0
	mov	v4.s[0], w9
	eor	v0.16b, v0.16b, v4.16b
	add	x1, x1, #64
	sub	x2, x2, #64
	ldr	q4, .Lcrc32_k0

2:
	cmp	x2, #64
	b.lo	3f
	ldp	q5, q6, [x1]
	ldp	q7, q16, [x1, #32]
	pmull	v17.1q, v0.1d, v4.1d
	eor	v17.16b, v17.16b, v5.16b
	pmull2	v0.1q, v0.2d, v4.2d
	eor	v0.16b, v0.16b, v17.16b
	pmull	v17.1q, v1.1d, v4.1d
	eor	v17.16b, v17.16b, v6.16b
	pmull2	v1.1q, v1.2d, v4.2d
	eor	v1.16b, v1.16b, v17.16b
	pmull	v17.1q, v2.1d, v4.1d
	eor	v17.16b, v17.16b, v7.16b
	pmull2	v2.1q, v2.2d, v4.2d
	eor	v2.16b, v2.16b, v17.16b
	pmull	v17.1q, v3.1d, v4.1d
	eor	v17.16b, v17.16b, v16.16b
	pmull2	v3.1q, v3.2d, v4.2d
	eor	v3.16b, v3.16b, v17.16b
	add	x1, x1, #64
	sub	x2, x2, #64
	b	2b

3:
	/* Reduce 4 accumulators to 1. */
	ldr	q4, .Lcrc32_k1
	pmull	v5.1q, v0.1d, v4.1d
	eor	v5.16b, v5.16b, v1.16b
	pmull2	v0.1q, v0.2d, v4.2d
	eor	v0.16b, v0.16b, v5.16b
	pmull	v5.1q, v2.1d, v4.1d
	eor	v5.16b, v5.16b, v3.16b
	pmull2	v2.1q, v2.2d, v4.2d
	eor	v2.16b, v2.16b, v5.16b
	ldr	q4, .Lcrc32_k2
	pmull	v5.1q, v0.1d, v4.1d
	eor	v5.16b, v5.16b, v2.16b
	pmull2	v0.1q, v0.2d, v4.2d
	eor	v0.16b, v0.16b, v5.16b
	mov	x10, v0.d[0]
	crc32x	w9, wzr, x10
	mov	x10, v0.d[1]
	crc32x	w9, w9, x10

5:
	/* 16..63 byte tail with a single vector accumulator. */
	cmp	x2, #16
	b.lo	6f
	ldr	q0, [x1], #16
	movi	v1.2d, #0
	mov	v1.s[0], w9
	eor	v0.16b, v0.16b, v1.16b
	sub	x2, x2, #16
	ldr	q1, .Lcrc32_k1
7:
	cmp	x2, #16
	b.lo	8f
	ldr	q2, [x1], #16
	pmull	v3.1q, v0.1d, v1.1d
	eor	v3.16b, v3.16b, v2.16b
	pmull2	v0.1q, v0.2d, v1.2d
	eor	v0.16b, v0.16b, v3.16b
	sub	x2, x2, #16
	b	7b
8:
	mov	x10, v0.d[0]
	crc32x	w9, wzr, x10
	mov	x10, v0.d[1]
	crc32x	w9, w9, x10

6:
	/* Byte tail. */
	cmp	x2, #8
	b.lo	9f
	ldr	x3, [x1], #8
	crc32x	w9, w9, x3
	sub	x2, x2, #8
9:
	cbz	x2, 10f
	ldrb	w3, [x1], #1
	crc32b	w9, w9, w3
	sub	x2, x2, #1
	b	9b
10:
	mov	w0, w9
	ret

.align 4
.Lcrc32_k0:
	.quad	0x000000008f352d95
	.quad	0x000000001d9513d7
.Lcrc32_k1:
	.quad	0x00000000ae689191
	.quad	0x00000000ccaa009e
.Lcrc32_k2:
	.quad	0x00000000f1da05aa
	.quad	0x0000000081256527
