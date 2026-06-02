/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "gunwinder/unwinder.h"
#include <pthread.h>
#include <string.h>

#define GU_PID_CTX_EVENT_LISTENER_MAX 16

static pthread_mutex_t pid_ctx_event_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_ctx_callback pid_ctx_event_cbs[GU_PID_CTX_EVENT_LISTENER_MAX];
static void *pid_ctx_event_ctxs[GU_PID_CTX_EVENT_LISTENER_MAX];

int gu_register_pid_ctx_event_listener(pid_ctx_callback callback, void *cb_ctx)
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
	pthread_mutex_unlock(&pid_ctx_event_lock);

	return 0;
}

static void pid_ctx_event_notify(const struct gu_pid_ctx_event *event)
{
	pid_ctx_callback cbs[GU_PID_CTX_EVENT_LISTENER_MAX] = { 0 };
	void *ctxs[GU_PID_CTX_EVENT_LISTENER_MAX] = { 0 };
	unsigned int n = 0;
	unsigned int i = 0;

	if (!event)
		return;

	pthread_mutex_lock(&pid_ctx_event_lock);
	for (i = 0; i < GU_PID_CTX_EVENT_LISTENER_MAX; i++) {
		if (!pid_ctx_event_cbs[i])
			continue;
		cbs[n] = pid_ctx_event_cbs[i];
		ctxs[n] = pid_ctx_event_ctxs[i];
		n++;
	}
	pthread_mutex_unlock(&pid_ctx_event_lock);

	for (i = 0; i < n; i++)
		cbs[i](event, ctxs[i]);
}

void gu_pid_ctx_event_notify_pid_ctx(int pid, unsigned long long start_time, const char *comm, unsigned int type)
{
	struct gu_pid_ctx_event event = { 0 };

	event.pid = pid;
	event.type = type;
	event.start_time = start_time;
	if (comm && comm[0]) {
		strncpy(event.comm, comm, sizeof(event.comm));
		event.comm[sizeof(event.comm) - 1] = '\0';
	}

	pid_ctx_event_notify(&event);
}
