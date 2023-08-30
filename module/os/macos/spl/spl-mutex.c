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
 * Copyright (C) 2013,2020 Jorgen Lundman <lundman@lundman.net>
 * Copyright (C) 2023 Sean Doran <smd@use.net>
 *
 */

#include <IOKit/IOLib.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <kern/thread.h>
#include <string.h>
#include <sys/debug.h>
#include <kern/debug.h>
#include <sys/thread.h>

// Not defined in headers
extern boolean_t lck_mtx_try_lock(lck_mtx_t *lck);

/*
 * SPL mutexes: use the XNU interface, rather than the ones below,
 * initialized in spl-osx.c and used in spl-thread.c
 */
lck_grp_attr_t	*spl_mtx_grp_attr;
lck_attr_t	*spl_mtx_lck_attr;
lck_grp_t	*spl_mtx_grp;

static lck_attr_t	*zfs_lock_attr = NULL;
static lck_grp_attr_t	*zfs_group_attr = NULL;

static lck_grp_t *zfs_mutex_group = NULL;

uint64_t zfs_active_mutex = 0;

#ifdef SPL_DEBUG_MUTEX
#include <sys/list.h>
static list_t mutex_list;
static kmutex_t mutex_list_mutex;
static kcondvar_t mutex_list_cv;


struct leak {
	list_node_t	mutex_leak_node;

#define	SPL_DEBUG_MUTEX_MAXCHAR 32
	char		location_file[SPL_DEBUG_MUTEX_MAXCHAR];
	char		location_function[SPL_DEBUG_MUTEX_MAXCHAR];
	uint64_t	location_line;
	void		*mp;

	uint64_t	wdlist_locktime;	// time lock was taken
	char		wdlist_file[32];	// storing holder
	int		wdlist_line;
	hrtime_t	wdlist_mutex_created;
	uint64_t	wdlist_total_lock_count;
	uint64_t	wdlist_total_trylock_success;
	uint64_t	wdlist_total_trylock_miss;
};

static int wdlist_exit = 0;

void
spl_wdlist_settime(void *mpleak, uint64_t value)
{
	struct leak *leak = (struct leak *)mpleak;
	VERIFY3P(leak, !=, NULL);
	atomic_store_nonatomic(&leak->wdlist_locktime, value);
}

inline static void
spl_wdlist_check(void *ignored)
{
	struct leak *mp;
	printf("SPL: Mutex watchdog is alive\n");

	mutex_enter(&mutex_list_mutex);
	while (!wdlist_exit) {

		(void) cv_timedwait(&mutex_list_cv,
		    &mutex_list_mutex, ddi_get_lbolt() +
		    SEC_TO_TICK(SPL_MUTEX_WATCHDOG_SLEEP));

		uint64_t noe = gethrestime_sec();
		for (mp = list_head(&mutex_list);
		    mp;
		    mp = list_next(&mutex_list, mp)) {
			uint64_t locktime = mp->wdlist_locktime;
			if ((locktime > 0) && (noe > locktime) &&
			    noe - locktime >= SPL_MUTEX_WATCHDOG_TIMEOUT) {
				printf("SPL: mutex (%p) held for %llus by "
				    "'%s':%d\n", mp, noe -
				    mp->wdlist_locktime, mp->wdlist_file,
				    mp->wdlist_line);
			} // if old
		} // for all
	} // while not exit

	wdlist_exit = 0;
	cv_signal(&mutex_list_cv);
	mutex_exit(&mutex_list_mutex);

	printf("SPL: watchdog thread exit\n");
	thread_exit();
}
#endif


int
spl_mutex_subsystem_init(void)
{
	zfs_lock_attr = lck_attr_alloc_init();
	zfs_group_attr = lck_grp_attr_alloc_init();
	zfs_mutex_group  = lck_grp_alloc_init("zfs-mutex", zfs_group_attr);

#ifdef SPL_DEBUG_MUTEX
	{
		unsigned char mutex[128];
		int i;

		memset(mutex, 0xAF, sizeof (mutex));
		lck_mtx_init((lck_mtx_t *)&mutex[0], zfs_mutex_group,
		    zfs_lock_attr);
		for (i = sizeof (mutex) -1; i >= 0; i--)
			if (mutex[i] != 0xAF)
				break;

		printf("SPL: %s:%d: mutex size is %u\n",
		    __func__, __LINE__, i+1);

	}

	list_create(&mutex_list, sizeof (struct leak),
	    offsetof(struct leak, mutex_leak_node));
	/* We can not call mutex_init() as it would use "leak" */
	lck_mtx_init((lck_mtx_t *)&mutex_list_mutex.m_lock, zfs_mutex_group,
	    zfs_lock_attr);
	mutex_list_mutex.m_initialised = MUTEX_INIT;
	cv_init(&mutex_list_cv, NULL, CV_DEFAULT, NULL);

	/* create without timesharing or qos */
	(void) thread_create_named_with_extpol_and_qos(
	    "spl_wdlist_check (mutex)",
	    NULL, NULL, NULL,
	    NULL, 0, spl_wdlist_check, NULL, 0, 0, maxclsyspri);
#endif /* SPL_DEBUG_MUTEX */
	return (0);
}

void
spl_mutex_subsystem_fini(void)
{
#ifdef SPL_DEBUG_MUTEX
	uint64_t total = 0;
	printf("SPL: %s:%d: Dumping leaked mutex allocations..."
	    " zfs_active_mutex == %llu\n",
	    __func__, __LINE__, atomic_load_64(&zfs_active_mutex));

	/* Ask the thread to quit */
	mutex_enter(&mutex_list_mutex);
	wdlist_exit = 1;
	while (wdlist_exit) {
		cv_signal(&mutex_list_cv);
		cv_wait(&mutex_list_cv, &mutex_list_mutex);
	}

	/* mutex watchdog thread has quit, we hold the mutex */

	/* walk the leak list */

	while (1) {
		struct leak *leak, *runner;
		uint32_t found;

		leak = list_head(&mutex_list);

		if (leak) {
			list_remove(&mutex_list, leak);
		}
		if (!leak)
			break;

		// Run through list and count up how many times this leak is
		// found, removing entries as we go.
		for (found = 1, runner = list_head(&mutex_list);
		    runner;
		    runner = runner ? list_next(&mutex_list, runner) :
		    list_head(&mutex_list)) {

			if (strcmp(leak->location_file, runner->location_file)
			    == 0 && strcmp(leak->location_function,
			    runner->location_function) == 0 &&
			    leak->location_line == runner->location_line) {
				// Same place
				found++;
				list_remove(&mutex_list, runner);
				IOFreeType(runner, struct leak);
				runner = NULL;
			} // if same

		} // for all nodes

		printf("SPL: %s:%d  mutex %p : %s %s %llu : # leaks: %u"
		    " created %llu seconds ago, locked %llu,"
		    "try_s %llu try_w %llu\n",
		    __func__, __LINE__,
		    leak->mp,
		    leak->location_file,
		    leak->location_function,
		    leak->location_line,
		    found,
		    NSEC2SEC(gethrtime() - leak->wdlist_mutex_created),
		    leak->wdlist_total_lock_count,
		    leak->wdlist_total_trylock_success,
		    leak->wdlist_total_trylock_miss);

		IOFreeType(leak, struct leak);
		total += found;

	}
	mutex_exit(&mutex_list_mutex);

	printf("SPL: %s:%d Dumped %llu leaked allocations.\n",
	    __func__, __LINE__, total);

	/* We can not call mutex_destroy() as it uses leak */
	lck_mtx_destroy((lck_mtx_t *)&mutex_list_mutex.m_lock, zfs_mutex_group);
	cv_destroy(&mutex_list_cv);
	list_destroy(&mutex_list);
#endif

	if (atomic_load_64(&zfs_active_mutex) != 0) {
		printf("SPL: %s:%d: zfs_active_mutex is %llu\n",
		    __func__, __LINE__, atomic_load_64(&zfs_active_mutex));
	} else {
		printf("SPL: %s: good, zero zfs_active_mutex\n",
		    __func__);
	}

	lck_attr_free(zfs_lock_attr);
	zfs_lock_attr = NULL;

	lck_grp_attr_free(zfs_group_attr);
	zfs_group_attr = NULL;

	lck_grp_free(zfs_mutex_group);
	zfs_mutex_group = NULL;
}



#ifdef SPL_DEBUG_MUTEX
void
spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc,
    const char *file, const char *fn, int line)
#else
void
spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc)
#endif
{
	ASSERT(type != MUTEX_SPIN);
	ASSERT3P(ibc, ==, NULL);

#ifdef SPL_DEBUG_MUTEX
	VERIFY3U(atomic_load_nonatomic(&mp->m_initialised), !=, MUTEX_INIT);
#endif

	lck_mtx_init((lck_mtx_t *)&mp->m_lock, zfs_mutex_group, zfs_lock_attr);
	mp->m_owner = NULL;
	mp->m_waiters = 0;
	mp->m_sleepers = 0;

	atomic_inc_64(&zfs_active_mutex);

#ifdef SPL_DEBUG_MUTEX
	mp->m_initialised = MUTEX_INIT;

	struct leak *leak;

	leak = IOMallocType(struct leak);

	VERIFY3P(leak, !=, NULL);

	memset(leak, 0, sizeof (struct leak));

	leak->wdlist_mutex_created = gethrtime();
	strlcpy(leak->location_file, file, SPL_DEBUG_MUTEX_MAXCHAR);
	strlcpy(leak->location_function, fn, SPL_DEBUG_MUTEX_MAXCHAR);
	leak->location_line = line;
	leak->mp = mp;

	mutex_enter(&mutex_list_mutex);
	list_link_init(&leak->mutex_leak_node);
	list_insert_tail(&mutex_list, leak);
	mp->leak = leak;
	mutex_exit(&mutex_list_mutex);
#endif

}

void
spl_mutex_destroy(kmutex_t *mp)
{
	if (!mp)
		return;

#ifdef SPL_DEBUG_MUTEX
	VERIFY3U(atomic_load_nonatomic(&mp->m_initialised), ==, MUTEX_INIT);
#endif

	if (atomic_load_nonatomic(&mp->m_owner) != 0)
		panic("SPL: releasing held mutex");

	lck_mtx_destroy((lck_mtx_t *)&mp->m_lock, zfs_mutex_group);

	atomic_dec_64(&zfs_active_mutex);

#ifdef SPL_DEBUG_MUTEX
	atomic_store_nonatomic(&mp->m_initialised, MUTEX_DESTROYED);

	struct leak *leak = (struct leak *)mp->leak;

	VERIFY3P(leak, !=, NULL);

#define	BUSY_LOCK_THRESHOLD			1000 * 1000
#define	BUSY_LOCK_PER_MILLISECOND_THRESHOLD	2

	if (leak->wdlist_total_lock_count > BUSY_LOCK_THRESHOLD) {
		const hrtime_t nsage =
		    gethrtime() - leak->wdlist_mutex_created;
		const uint64_t msage = NSEC2MSEC(nsage) + 1;

		if (leak->wdlist_total_lock_count / msage >
		    BUSY_LOCK_PER_MILLISECOND_THRESHOLD) {
			const uint64_t secage = NSEC2MSEC(nsage);

			printf("SPL: %s:%d: destroyed hot lock"
			    " %llu mutex_enters since creation"
			    " %llu seconds ago last lock at %s:%d\n",
			    __func__, __LINE__,
			    leak->wdlist_total_lock_count,
			    secage,
			    leak->wdlist_file, leak->wdlist_line);
		}
	}

#define	TRYLOCK_WAIT_RATIO	2
#define	TRYLOCK_CALL_THRESHOLD	1000 * 1000

	const uint64_t try_calls =
	    leak->wdlist_total_trylock_success +
	    leak->wdlist_total_trylock_miss;

	if (try_calls > TRYLOCK_CALL_THRESHOLD) {
		const uint64_t denom =
		    MAX(leak->wdlist_total_trylock_miss, 1);

		const uint64_t ratio = try_calls / denom;

		if (ratio > TRYLOCK_WAIT_RATIO) {
			printf("SPL: %s:%d: destroyed lock which"
			    " waited often in mutex_trylock,"
			    " %llu all locks"
			    " %llu trysuccess %llu miss, ratio %llu"
			    " created %llu seconds ago last lock at %s:%d\n",
			    __func__, __LINE__,
			    leak->wdlist_total_lock_count,
			    leak->wdlist_total_trylock_success,
			    leak->wdlist_total_trylock_miss,
			    ratio,
			    NSEC2SEC(gethrtime() -
				leak->wdlist_mutex_created),
			    leak->wdlist_file, leak->wdlist_line);
		}
	}

	mutex_enter(&mutex_list_mutex);
	list_remove(&mutex_list, leak);
	mp->leak = NULL;
	mutex_exit(&mutex_list_mutex);
	IOFreeType(leak, struct leak);
#endif
}

#ifdef SPL_DEBUG_MUTEX
void
spl_mutex_enter(kmutex_t *mp, const char *file, int line)
#else
void
spl_mutex_enter(kmutex_t *mp)
#endif
{
#ifdef SPL_DEBUG_MUTEX
	VERIFY3U(atomic_load_nonatomic(&mp->m_initialised), ==, MUTEX_INIT);
#endif

#ifdef DEBUG
	if (unlikely(*((uint64_t *)mp) == 0xdeadbeefdeadbeef)) {
		panic("SPL: mutex_enter deadbeef");
		__builtin_unreachable();
	}
#endif

	if (atomic_load_nonatomic(&mp->m_owner) == current_thread()) {
		panic("mutex_enter: locking against myself!");
		__builtin_unreachable();
	}

	atomic_inc_64(&mp->m_waiters);
	spl_data_barrier();
	lck_mtx_lock((lck_mtx_t *)&mp->m_lock);
	spl_data_barrier();
	atomic_dec_64(&mp->m_waiters);
	atomic_store_nonatomic(&mp->m_owner, current_thread());

#ifdef SPL_DEBUG_MUTEX
	if (likely(mp->leak)) {
		struct leak *leak = (struct leak *)mp->leak;
		leak->wdlist_locktime = gethrestime_sec();
		strlcpy(leak->wdlist_file, file, sizeof (leak->wdlist_file));
		leak->wdlist_line = line;
		leak->wdlist_total_lock_count++;
	} else {
		panic("SPL: %s:%d: where is my leak data?"
		    " possible compilation mismatch", __func__, __LINE__);
		__builtin_unreachable();
	}
#endif

}

void
spl_mutex_exit(kmutex_t *mp)
{
#ifdef DEBUG
	if (unlikely(*((uint64_t *)mp) == 0xdeadbeefdeadbeef)) {
		panic("SPL: mutex_exit deadbeef");
		__builtin_unreachable();
	}
#endif

#ifdef SPL_DEBUG_MUTEX
	VERIFY3U(atomic_load_nonatomic(&mp->m_initialised), ==, MUTEX_INIT);
#endif

#ifdef SPL_DEBUG_MUTEX
	if (likely(mp->leak)) {
		struct leak *leak = (struct leak *)mp->leak;
		uint64_t locktime = leak->wdlist_locktime;
		uint64_t noe = gethrestime_sec();
		if ((locktime > 0) && (noe > locktime) &&
		    noe - locktime >= SPL_MUTEX_WATCHDOG_TIMEOUT) {
			printf("SPL: mutex (%p) finally released after %llus "
			    "by '%s':%d\n", leak, noe - leak->wdlist_locktime,
			    leak->wdlist_file, leak->wdlist_line);
		}
		leak->wdlist_locktime = 0;
		leak->wdlist_file[0] = 0;
		leak->wdlist_line = 0;
	} else {
		panic("SPL: %s:%d: where is my leak data?",
		    __func__, __LINE__);
		__builtin_unreachable();
	}
#endif
	mp->m_owner = NULL;
	spl_data_barrier();
	lck_mtx_unlock((lck_mtx_t *)&mp->m_lock);
}

int
spl_mutex_tryenter(kmutex_t *mp)
{
	int held;

#ifdef SPL_DEBUG_MUTEX
	VERIFY3U(atomic_load_nonatomic(&mp->m_initialised), ==, MUTEX_INIT);
#endif

	atomic_inc_64(&mp->m_waiters);
	spl_data_barrier();
	held = lck_mtx_try_lock((lck_mtx_t *)&mp->m_lock);
	/*
	 * Now do a full barrier, because that's the right thing to do after
	 * we get a lock from lck_mtx...(), which on Apple Silicon uses softer
	 * acquire semantics than the multithread store ordering we'd like
	 * in our emulation of heritage Solaris code.
	 *
	 * Apple Silicon relevant only.  spl_data_barrier() is a noop on
	 * strong memory model machines like Intel.
	 *
	 * Initially this was an unconditional spl_data_barrier(), but the
	 * point of the barrier is to let other threads know we have the lock
	 * in happens-before sense (i.e., that the lock is held before the
	 * other threads issue reads/writes on the affected cache lines, and
	 * every thread enjoys happens-after on any reads/writes of those
	 * cache lines after the barrier is issued).  The "dmb ish" is cheap
	 * but not free, and there could be a mutex_tryenter() in a fairly
	 * tight loop.  So we skip it if we don't obtain the lock.  We've also
	 * recently done a full barrier so that we know that a previous lock
	 * holder's mutex_exit() is in a happened-before state when we do
	 * lck_mtx_try_lock().
	 *
	 * The atomic_dec_64() will use acquire/release semantics and who
	 * knows how they slide around relative to the full barrier (it also
	 * is not necessarily a super-fast instruction), so we don't want to
	 * slide the barrier into a single if (held) after the atomic decrement.
	 *
	 * The atomic decrement also needs to happen before DEBUGging code, so
	 * it should stay close to the lck_mtx...().
	 */
	if (held)
		spl_data_barrier();
	atomic_dec_64(&mp->m_waiters);
	if (held) {
		atomic_store_nonatomic(&mp->m_owner, current_thread());

#ifdef SPL_DEBUG_MUTEX
	if (likely(mp->leak)) {
		struct leak *leak = (struct leak *)mp->leak;
		leak->wdlist_locktime = gethrestime_sec();
		if (held) {
			leak->wdlist_total_trylock_success++;
			leak->wdlist_total_lock_count++;
		} else {
			atomic_inc_64(&leak->wdlist_total_trylock_miss);
		}
	} else {
		panic("SPL: %s:%d: where is my leak data?",
		    __func__, __LINE__);
		__builtin_unreachable();
	}
#endif

	}
	return (held);
}

int
spl_mutex_owned(kmutex_t *mp)
{
	return (atomic_load_nonatomic(&mp->m_owner) == current_thread());
}

struct kthread *
spl_mutex_owner(kmutex_t *mp)
{
	return (atomic_load_nonatomic(&mp->m_owner));
}

#ifdef SPL_DEBUG_MUTEX
void
spl_dbg_mutex_destroy(kmutex_t *mp, const char *func,
    const char *file, const int line)
{

	extern struct thread *spl_mutex_owner(kmutex_t *);
	extern int spl_mutex_owned(kmutex_t *);
	extern void spl_mutex_destroy(kmutex_t *);

	membar_consumer();
	VERIFY3P(mp, !=, NULL);
	struct thread *o = spl_mutex_owner(mp);
	if (o != NULL) {
		VERIFY3P(mp->leak, !=, NULL);
		struct leak *leak = (struct leak *)mp->leak;
		uint64_t noe = gethrestime_sec();
		if (!spl_mutex_owned(mp)) {
			panic("%s: mutex has other owner %p"
			    " destroy call at %s() in %s line %d,"
			    " last mutex_enter in %s line %d"
			    " %llus ago"
			    "\n",
			    __func__, o, func, file, line,
			    leak->wdlist_file,
			    leak->wdlist_line,
			    noe - leak->wdlist_locktime);
		} else {
			panic("%s: mutex %p is owned by"
			    " current thread"
			    " from %s() in %s line %d"
			    " last mutex_enter in %s line %d"
			    " %llus ago"
			    "\n",
			    __func__, o, func, file, line,
			    leak->wdlist_file,
			    leak->wdlist_line,
			    noe - leak->wdlist_locktime);
		}
	}
	spl_mutex_destroy(mp);
}
#endif
