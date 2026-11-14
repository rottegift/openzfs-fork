// SPDX-License-Identifier: CDDL-1.0
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * https://opensource.org/license/CDDL-1.0.
 */

#ifndef _SYS_ZFS_DEBUG_OS_H
#define	_SYS_ZFS_DEBUG_OS_H

#define	 SET_ERROR(err) \
	(__set_error(__FILE__, __func__, __LINE__, err), err)

#ifdef _KERNEL
/* See the comment in <sys/cmn_err.h>. */
#ifdef __cplusplus
extern "C" {
#endif
extern void (panic)(const char *, ...)
    __attribute__((__noreturn__, __format__(__printf__, 1, 2)));
#ifdef __cplusplus
}
#endif
#endif

#endif	/* _SYS_ZFS_DEBUG_OS_H */
