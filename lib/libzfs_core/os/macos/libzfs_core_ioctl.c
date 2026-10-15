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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/zfs_ioctl.h>
#include <os/macos/zfs/sys/zfs_ioctl_compat.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <libnvpair.h>
#include <libzfs_core.h>
#include "libzfs_core_impl.h"

/* As the kernel names it, see zfs_context_os.h */
#ifndef zc_fd_offset
#define	zc_fd_offset zc_zoneid
#endif

static int
zcmd_ioctl_compat(int fd, int request, zfs_cmd_t *zc, const int cflag)
{
	int ret;
	void *zc_c;
	unsigned long ncmd;
	zfs_iocparm_t zp;

	switch (cflag) {
	case ZFS_CMD_COMPAT_NONE:
		ncmd = _IOWR('Z', request, zfs_iocparm_t);
		zp.zfs_cmd = (uint64_t)zc;
		zp.zfs_cmd_size = sizeof (zfs_cmd_t);
		zp.zfs_ioctl_version = ZFS_IOCVER_ZOF;
		zp.zfs_ioc_error = 0;

		ret = ioctl(fd, ncmd, &zp);

		/*
		 * If ioctl worked, get actual rc from kernel, which goes
		 * into errno, and return -1 if not-zero.
		 */
		if (ret == 0) {
			errno = zp.zfs_ioc_error;
			if (zp.zfs_ioc_error != 0)
				ret = -1;
		}
		return (ret);

	default:
		abort();
		return (EINVAL);
	}

	/* Pass-through ioctl, rarely used if at all */

	ret = ioctl(fd, ncmd, zc_c);
	ASSERT0(ret);

	zfs_cmd_compat_get(zc, (caddr_t)zc_c, cflag);
	free(zc_c);

	return (ret);
}

/*
 * This is the macOS version of ioctl(). Because the XNU kernel
 * handles copyin() and copyout(), we must return success from the
 * ioctl() handler (or it will not copyout() for userland),
 * and instead embed the error return value in the zc structure.
 */
/*
 * The fd that a send, receive or diff ioctl moves its stream through, or
 * -1. The new-style ioctls carry it in their input nvlist.
 */
static int
lzc_ioctl_data_fd(unsigned long request, zfs_cmd_t *zc)
{
	const char *key;
	nvlist_t *nvl = NULL;
	int32_t datafd = -1;

	switch (request) {
	case ZFS_IOC_SEND:
	case ZFS_IOC_RECV:
	case ZFS_IOC_DIFF:
		return ((int)zc->zc_cookie);
	case ZFS_IOC_SEND_NEW:
		key = "fd";
		break;
	case ZFS_IOC_RECV_NEW:
		key = "input_fd";
		break;
	default:
		return (-1);
	}

	if (zc->zc_nvlist_src == 0 || nvlist_unpack(
	    (char *)(uintptr_t)zc->zc_nvlist_src, zc->zc_nvlist_src_size,
	    &nvl, 0) != 0)
		return (-1);
	(void) nvlist_lookup_int32(nvl, key, &datafd);
	nvlist_free(nvl);
	return (datafd);
}

int
lzc_ioctl_fd_os(int fd, unsigned long request, zfs_cmd_t *zc)
{
	size_t oldsize;
	int ret, cflag = ZFS_CMD_COMPAT_NONE;
	int datafd;
	off_t start = -1;

	/*
	 * The kernel cannot see where a regular file's offset is, so tell
	 * it in zc_fd_offset, and move ours to where it stopped. Without
	 * this "zfs send -R > file" and "zfs recv < file" read and write
	 * at offset 0. Pipes and sockets fail lseek() and are left alone.
	 */
	datafd = lzc_ioctl_data_fd(request, zc);
	if (datafd >= 0) {
		/* ">>" opens O_APPEND, whose offset is 0 until written */
		int fl = fcntl(datafd, F_GETFL);
		start = lseek(datafd, 0,
		    (fl != -1 && (fl & O_APPEND)) ? SEEK_END : SEEK_CUR);
	}
	if (start >= 0)
		zc->zc_fd_offset = start;

	oldsize = zc->zc_nvlist_dst_size;
	ret = zcmd_ioctl_compat(fd, request, zc, cflag);

	if (start >= 0) {
		int saved = errno;
		(void) lseek(datafd, zc->zc_fd_offset, SEEK_SET);
		errno = saved;
	}

	if (ret == 0 && oldsize < zc->zc_nvlist_dst_size) {
		ret = -1;
		errno = ENOMEM;
	}

	return (ret);
}
