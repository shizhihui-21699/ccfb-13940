#!/bin/sh
# Reproduces a kernel deadlock that this project's test harness is shaped around.
#
# On APFS (macOS 26.5.1, Darwin 25.5.0) two threads calling
# renamex_np(a, b, RENAME_SWAP) on the SAME pair of paths eventually deadlock in
# the kernel: one thread never returns from the syscall, and `kill -9` cannot
# reap it once it is stuck. No Rust, no safefs, twenty lines of C.
#
# Usage: scripts/verify_kernel_swap_bug.sh
#
# Exit status 0 means "the bug is still present" (the harness's single-swapper
# design is therefore required, not merely preferred).

set -u
dir=$(mktemp -d /tmp/swapbug.XXXXXX)
cc -O2 -o "$dir/swapbug" -x c - -lpthread <<'EOF'
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
static volatile int stop = 0;
static char dir[256];
static volatile long swaps = 0;
static void *swapper(void *arg) {
    char a[512], b[512];
    (void)arg;
    snprintf(a, sizeof a, "%s/a", dir);
    snprintf(b, sizeof b, "%s/b", dir);
    while (!stop) { renamex_np(a, b, RENAME_SWAP); __sync_fetch_and_add(&swaps, 1); }
    return NULL;
}
int main(void) {
    char cmd[768];
    pthread_t t[2];
    {
        const char *e = getenv("SWAPBUG_DIR");
        snprintf(dir, sizeof dir, "%s", e ? e : "/tmp/swapbug-work");
    }
    snprintf(cmd, sizeof cmd, "mkdir -p %s && echo L > %s/a && echo E > %s/b", dir, dir, dir);
    if (system(cmd) != 0) return 2;
    pthread_create(&t[0], NULL, swapper, NULL);
    pthread_create(&t[1], NULL, swapper, NULL);
    sleep(3);
    stop = 1;
    pthread_join(t[0], NULL);
    pthread_join(t[1], NULL);
    printf("no deadlock (%ld swaps)\n", swaps);
    return 0;
}
EOF
if [ ! -x "$dir/swapbug" ]; then
    echo "could not compile the reproducer" >&2
    exit 2
fi
# The reproducer must be killed from *outside*: once wedged, the process does
# not return from the syscall, so an in-process `alarm` handler cannot run
# either (which is itself part of the bug). The script therefore runs the
# binary in the background, waits a bounded time, and reports what it finds.
SWAPBUG_DIR="$dir/target" "$dir/swapbug" </dev/null &
child=$!
deadline=$(( $(date +%s) + 12 ))
while kill -0 "$child" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "reproduced: concurrent RENAME_SWAP on one path pair wedged the kernel"
        echo "  (the process never returned and cannot be reaped; that is the bug)"
        pkill -9 -f "$dir/swapbug" 2>/dev/null
        exit 0
    fi
    sleep 1
done
wait "$child"
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "kernel behaved correctly: the single-swapper workaround may be unnecessary"
    exit 1
fi
echo "reproducer exited $rc without wedging" >&2
exit 2
