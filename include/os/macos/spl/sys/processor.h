/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 *
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#ifndef	_SPL_PROCESSOR_H
#define	_SPL_PROCESSOR_H

#include <sys/types.h>

extern uint32_t getcpuid(void);

#if defined(__amd64__) || defined(__i386__)

extern int __cpuid_count(unsigned int __level, unsigned int __sublevel,
	unsigned int __eax, unsigned int __ebx,
	unsigned int __ecx, unsigned int __edx);

#define	__cpuid_count(level, count, a, b, c, d) \
	__asm__("xchg{l}\t{%%}ebx, %1\n\t" \
		"cpuid\n\t" \
		"xchg{l}\t{%%}ebx, %1\n\t" \
		: "=a" (a), "=r" (b), "=c" (c), "=d" (d) \
		: "0" (level), "2" (count))

#define	__cpuid(level, a, b, c, d) \
	__asm__("xchg{l}\t{%%}ebx, %1\n\t" \
		"cpuid\n\t" \
		"xchg{l}\t{%%}ebx, %1\n\t" \
		: "=a" (a), "=r" (b), "=c" (c), "=d" (d) \
		: "0" (level))

static inline unsigned int
__get_cpuid_max(unsigned int __ext, unsigned int *__sig)
{
	unsigned int __eax, __ebx, __ecx, __edx;
	__cpuid(__ext, __eax, __ebx, __ecx, __edx);
	if (__sig)
		*__sig = __ebx;
	return (__eax);
}

/* macOS does have do_cpuid() macro */
static inline int
__get_cpuid(unsigned int __level,
    unsigned int *__eax, unsigned int *__ebx,
    unsigned int *__ecx, unsigned int *__edx)
{
	unsigned int __ext = __level & 0x80000000;
	if (__get_cpuid_max(__ext, 0) < __level)
		return (0);
	__cpuid(__level, *__eax, *__ebx, *__ecx, *__edx);
	return (1);
}

#endif // x86

typedef int	processorid_t;
extern int spl_processor_init(void);

#endif /* _SPL_PROCESSOR_H */
