/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "gunwinder/unwinder.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#define GU_PID_CTX_EVENT_LISTENER_MAX 16

static pthread_mutex_t pid_ctx_event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pid_ctx_event_cond = PTHREAD_COND_INITIALIZER;
static pid_ctx_callback pid_ctx_event_cbs[GU_PID_CTX_EVENT_LISTENER_MAX];
static void *pid_ctx_event_ctxs[GU_PID_CTX_EVENT_LISTENER_MAX];
static unsigned int pid_ctx_event_waitable[GU_PID_CTX_EVENT_LISTENER_MAX];
static unsigned int pid_ctx_event_active[GU_PID_CTX_EVENT_LISTENER_MAX];
static atomic_uint pid_ctx_event_listener_count = 0;

static unsigned int gu_pid_ctx_event_listener_count(void)
{
	return atomic_load_explicit(&pid_ctx_event_listener_count,
				    memory_order_acquire);
}

static int gu_register_pid_ctx_event_listener_common(pid_ctx_callback callback,
						     void *cb_ctx,
						     unsigned int waitable)
{
	unsigned int i = 0;

	if (!callback)
		return -1;

	pthread_mutex_lock(&pid_ctx_event_lock);
	for (i = 0; i < GU_PID_CTX_EVENT_LISTENER_MAX; i++) {
		if (pid_ctx_event_cbs[i])
			continue;
		break;
	}

	if (i >= GU_PID_CTX_EVENT_LISTENER_MAX) {
		pthread_mutex_unlock(&pid_ctx_event_lock);
		return -1;
	}

	pid_ctx_event_cbs[i] = callback;
	pid_ctx_event_ctxs[i] = cb_ctx;
	pid_ctx_event_waitable[i] = waitable ? 1 : 0;
	atomic_fetch_add_explicit(&pid_ctx_event_listener_count, 1,
				  memory_order_release);
	pthread_mutex_unlock(&pid_ctx_event_lock);

	return 0;
}

int gu_register_pid_ctx_event_listener(pid_ctx_callback callback, void *cb_ctx)
{
	return gu_register_pid_ctx_event_listener_common(callback, cb_ctx, 0);
}

int gu_register_pid_ctx_event_listener_waitable(pid_ctx_callback callback,
					       void *cb_ctx)
{
	return gu_register_pid_ctx_event_listener_common(callback, cb_ctx, 1);
}

int gu_unregister_pid_ctx_event_listener(pid_ctx_callback callback, void *cb_ctx)
{
	unsigned int i = 0;
	int removed = 0;

	if (!callback)
		return -1;

	pthread_mutex_lock(&pid_ctx_event_lock);
	for (i = 0; i < GU_PID_CTX_EVENT_LISTENER_MAX; i++) {
		if (pid_ctx_event_cbs[i] != callback ||
		    pid_ctx_event_ctxs[i] != cb_ctx)
			continue;

		pid_ctx_event_cbs[i] = NULL;
		pid_ctx_event_ctxs[i] = NULL;
		pid_ctx_event_waitable[i] = 0;
		atomic_fetch_sub_explicit(&pid_ctx_event_listener_count, 1,
					  memory_order_release);
		removed = 1;
		while (pid_ctx_event_active[i] > 0)
			pthread_cond_wait(&pid_ctx_event_cond, &pid_ctx_event_lock);
	}
	pthread_mutex_unlock(&pid_ctx_event_lock);

	return removed ? 0 : -1;
}

static void pid_ctx_event_notify(const struct gu_pid_ctx_event *event)
{
	pid_ctx_callback cbs[GU_PID_CTX_EVENT_LISTENER_MAX] = { 0 };
	void *ctxs[GU_PID_CTX_EVENT_LISTENER_MAX] = { 0 };
	unsigned int slots[GU_PID_CTX_EVENT_LISTENER_MAX] = { 0 };
	unsigned int n = 0;
	unsigned int waitable_count = 0;
	unsigned int i = 0;

	if (!event)
		return;
	if (gu_pid_ctx_event_listener_count() == 0)
		return;

	pthread_mutex_lock(&pid_ctx_event_lock);
	for (i = 0; i < GU_PID_CTX_EVENT_LISTENER_MAX; i++) {
		if (!pid_ctx_event_cbs[i])
			continue;

		cbs[n] = pid_ctx_event_cbs[i];
		ctxs[n] = pid_ctx_event_ctxs[i];
		if (pid_ctx_event_waitable[i]) {
			slots[waitable_count++] = i;
			pid_ctx_event_active[i]++;
		}
		n++;
	}
	pthread_mutex_unlock(&pid_ctx_event_lock);

	for (i = 0; i < n; i++)
		cbs[i](event, ctxs[i]);

	if (waitable_count == 0)
		return;

	pthread_mutex_lock(&pid_ctx_event_lock);
	for (i = 0; i < waitable_count; i++) {
		pid_ctx_event_active[slots[i]]--;
		if (pid_ctx_event_active[slots[i]] == 0)
			pthread_cond_broadcast(&pid_ctx_event_cond);
	}
	pthread_mutex_unlock(&pid_ctx_event_lock);
}

void gu_pid_ctx_event_notify_pid_ctx(int pid, unsigned long long start_time, const char *comm, unsigned int type)
{
	struct gu_pid_ctx_event event = { 0 };

	if (gu_pid_ctx_event_listener_count() == 0)
		return;

	event.pid = pid;
	event.type = type;
	event.start_time = start_time;
	if (comm && comm[0]) {
		strncpy(event.comm, comm, sizeof(event.comm));
		event.comm[sizeof(event.comm) - 1] = '\0';
	}

	pid_ctx_event_notify(&event);
}
