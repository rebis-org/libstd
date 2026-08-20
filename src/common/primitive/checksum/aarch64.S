#ifdef __APPLE__
#define SYM(x) _##x
#define HIDDEN(x) .private_extern x
#else
#define SYM(x) x
#define HIDDEN(x) .hidden x
#endif

.text
.arch_extension crc
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
