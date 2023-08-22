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
 * Copyright (C) 2008 MacZFS
 * Copyright (C) 2013, 2020 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/thread.h>
#include <mach/thread_act.h>
#include <sys/kmem.h>
#include <sys/tsd.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/callb.h>
#include <sys/systm.h>
#include <TargetConditionals.h>
#include <AvailabilityMacros.h>

uint64_t zfs_threads = 0;

kthread_t *
spl_thread_create_named(
    const char *name,
    caddr_t stk,
    size_t stksize,
    void (*proc)(void *),
    void *arg,
    size_t len,
    int state,
#ifdef SPL_DEBUG_THREAD
    const char *filename,
    int line,
#endif
    pri_t pri)
{
	thread_extended_policy_data_t tmsharepol = {
		.timeshare = TRUE
	};

	return (spl_thread_create_named_with_extpol_and_qos(
	    &tmsharepol, NULL, NULL,
	    name, stk, stksize, proc, arg,
	    len, state,
#ifdef SPL_DEBUG_THREAD
	    filename, line,
#endif
	    pri));
}

/*
 * For each of the first three args, if NULL then kernel default
 *
 * no timesharing, no througput qos, no latency qos
 */

kthread_t *
spl_thread_create_named_with_extpol_and_qos(
    thread_extended_policy_data_t *tmsharepol,
    thread_throughput_qos_policy_data_t *thoughpol,
    thread_latency_qos_policy_t *latpol,
    const char *name,
    caddr_t stk,
    size_t stksize,
    void (*proc)(void *),
    void *arg,
    size_t len,
    int state,
#ifdef SPL_DEBUG_THREAD
    const char *filename,
    int line,
#endif
    pri_t pri)
{
	kern_return_t result;
	thread_t thread;

#ifdef SPL_DEBUG_THREAD
	printf("Start thread pri %d by '%s':%d\n", pri,
	    filename, line);
#endif

	/* * * *
	 * * * *
	 * Here we want to have some wrapper that takes as
	 * an argument { .proc = proc, .arg = arg, rendezvous = mtx} and waits
	 * until it is told to make forward progress, after we have
	 * twiddled with the settings.
	 *
	 * Alternatively, have the wrapper for proc do the settings
	 * twiddling
	 */
	result = kernel_thread_start((thread_continue_t)proc, arg, &thread);

	if (result != KERN_SUCCESS)
		return (NULL);

	set_thread_importance(thread, pri, "anonymous new zfs thread");

	/* set up thread */

	if (tmsharepol) {
		spl_set_thread_timeshare(thread, tmsharepol, name);
	}

	if (throughpol) {
		if (tmsharepol) {
			ASSERT(tmshare->timeshare, name);
		}
		spl_set_thread_throughput(thread, throughpol, name);
	}

	if (latpol) {
		if (tmsharepol) {
			ASSERT(tmshare->timeshare);
		}
		spl_set_thread_latency(thread, latpol);
	}

	if (name == NULL)
		name = "unnamed zfs thread";

#if	defined(MAC_OS_X_VERSION_10_15) && \
	(MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_15)
	thread_set_thread_name(thread, name);
#endif

	thread_deallocate(thread);

	atomic_inc_64(&zfs_threads);

	return ((kthread_t *)thread);
}

kthread_t *
spl_current_thread(void)
{
	thread_t cur_thread = current_thread();
	return ((kthread_t *)cur_thread);
}

__attribute__((noreturn)) void
spl_thread_exit(void)
{
	atomic_dec_64(&zfs_threads);

	tsd_thread_exit();
	(void) thread_terminate(current_thread());
	__builtin_unreachable();
}


/*
 * IllumOS has callout.c - place it here until we find a better place
 */
callout_id_t
timeout_generic(int type, void (*func)(void *), void *arg,
    hrtime_t expiration, hrtime_t resolution, int flags)
{
	struct timespec ts;
	hrt2ts(expiration, &ts);
	bsd_timeout(func, arg, &ts);
	/*
	 * bsd_untimeout() requires func and arg to cancel the timeout, so
	 * pass it back as the callout_id. If we one day were to implement
	 * untimeout_generic() they would pass it back to us
	 */
	return ((callout_id_t)arg);
}

/*
 * Set xnu kernel thread importance based on openzfs pri_t.
 *
 * Thread importance adjusts upwards and downards from BASEPRI_KERNEL (defined
 * as 81).  Higher value is higher priority (e.g. BASEPRI_REALTIME is 96),
 * BASEPRI_GRAPHICS is 76, and MAXPRI_USER is 63.
 *
 * (See osfmk/kern/sched.h)
 *
 * Many important kernel tasks run at BASEPRI_KERNEL,
 * with networking and kernel graphics (Metal etc) running
 * at BASEPRI_KERNEL + 1.
 *
 * We want maxclsyspri threads to have less xnu priority
 * BASEPRI_KERNEL, so as to avoid UI stuttering, network
 * disconnection and other side-effects of high zfs load with
 * high thread priority.
 *
 * In <sysmacros.h> we define maxclsyspri to 80 with
 * defclsyspri and minclsyspri set below that.
 */

void
spl_set_thread_importance(thread_t thread, pri_t pri, const char *name)
{
	thread_precedence_policy_data_t policy = { 0 };

	/*
	 * start by finding an offset from BASEPRI_KERNEL,
	 * which is found in osfmk/kern/sched.h
	 *
	 * (it's 81, importance is a signed-offset from that)
	 */

	policy.importance = pri - 81;

	/*
	 * dont let ANY of our threads run as high as networking & GPU
	 *
	 * hard cap on our maximum priority at 81 (BASEPRI_KERNEL),
	 * which is then our maxclsyspri.
	 */
	if (policy.importance > 0)
		policy.importance = 0;
	/*
	 * set a floor on importance at priority 60, which is about the same
	 * as bluetoothd and userland audio, which are of relatively high
	 * importance.
	 */
	else if (policy.importance < (-21))
		policy.importance = -21;

	int i = policy.importance;
	kern_return_t pol_prec_kret = thread_policy_set(thread,
	    THREAD_PRECEDENCE_POLICY,
	    (thread_policy_t)&policy,
	    THREAD_PRECEDENCE_POLICY_COUNT);
	if (pol_prec_kret != KERN_SUCCESS) {
		printf("SPL: %s:%d: ERROR failed to set"
		    " thread precedence to %d ret %d name %s\n",
		    __func__, __LINE__, i, pol_prec_kret, name);
	}
}

/*
 * Set a kernel throughput qos for this thread,
 */

void
spl_set_thread_throughput(thread_t thread,
    thread_throughput_qos_t *throughput, const char *name)
{


	ASSERT(throughput);

	if (!throughput)
		return;

	if (!name)
		name = "anonymous zfs thread (throughput)";

        /*
	 * TIERs: 0 is USER_INTERACTIVE, 1 is USER_INITIATED, 1 is LEGACY,
	 *        2 is UTILITY, 5 is BACKGROUND, 5 is MAINTENANCE
	 *
	 *  (from xnu/osfmk/kern/thread_policy.c)
	 */

	kern_return_t qoskret = thread_policy_set(thread,
	    THREAD_THROUGHPUT_QOS_POLICY,
	    (thread_policy_t)&qosp,
	    THREAD_THROUGHPUT_QOS_POLICY_COUNT);
	if (qoskret != KERN_SUCCESS) {
		printf("SPL: %s:%d: WARNING failed to set"
		    " thread throughput policy retval: %d "
		    " (THREAD_THROUGHPUT_QOS_POLICY %x), %s\n",
		    __func__, __LINE__, qoskret,
		    qosp.thread_throughput_qos_tier, name);
	}
}

void
spl_set_thread_latency(thread_t thread,
    thread_latency_qos_t *latency, const char *name)
{

	ASSERT(latency);

	if (!latency)
		return;

	if (!name)
		name = "anonymous zfs thread (latency)";

        /*
	 * TIERs: 0 is USER_INTERACTIVE, 1 is USER_INITIATED, 1 is LEGACY,
	 *        3 is UTILITY, 3 is BACKGROUND, 5 is MAINTENANCE
	 *
	 *  (from xnu/osfmk/kern/thread_policy.c)
	 *
	 * NB: these differ from throughput tier mapping
	 */

	kern_return_t qoskret = thread_policy_set(thread,
	    THREAD_LATENCY_QOS_POLICY,
	    (thread_policy_t) policy,
	    THREAD_LATENCY_QOS_POLICY_COUNT);
	if (qoskret != KERN_SUCCESS) {
		printf("SPL: %s:%d: WARNING failed to set"
		    " thread latency policy to %x, retval: %d, '%s'\n",
		    __func__, __LINE__,
		    latency->thread_latency_qos_tier,
		    qoskret,
		    name);
	}
}

/*
 * XNU will dynamically adjust TIMESHARE
 * threads around the chosen thread priority.
 * The lower the importance (signed value),
 * the more XNU will adjust a thread.
 * Threads may be adjusted *upwards* from their
 * base priority by XNU as well.
 */

void
spl_set_thread_timeshare(thread_t thread,
    thread_extended_policy_data_t *policy,
    const char *name)
{

	ASSERT(policy);

	if (!policy)
		return;

	if (!name) {
		if (policy->timeshare)
			name = "anonymous zfs thread (timeshare->off)";
		else
			name = "anonymous zfs thread (timeshare->on)";
	}

	kern_return_t kret = thread_policy_set(thread,
	    THREAD_EXTENDED_POLICY,
	    (thread_policy_t)&policy,
	    THREAD_EXTENDED_POLICY_COUNT);
	if (kret != KERN_SUCCESS) {
		printf("SPL: %s:%d: WARNING failed to set"
		    " timeshare policy to %d, retval: %d, %s\n",
		    __func__, __LINE__, kret,
		    policy->timeshare, name);
	}
}
