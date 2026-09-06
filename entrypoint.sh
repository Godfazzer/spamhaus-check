#!/bin/sh
# entrypoint.sh
# Version: 3.1.1
#
# Runs the Spamhaus check once a day at a fixed wall-clock time (RUN_AT,
# default 09:00) in the container's timezone (TZ, set in the Dockerfile
# to Europe/Kyiv) - NOT on a rolling interval. SPAMHAUS_DQS_KEY,
# ZABBIX_SERVER and ZABBIX_HOST are read from the container environment
# (pass with `-e` at `podman run` time, or via .env with podman-compose).
# Output goes to stdout/stderr, visible via `podman logs`.
set -eu

# As PID 1 inside the container, this script gets no default signal
# handling from the kernel - without an explicit trap, `podman stop`
# waits out its full timeout and falls back to SIGKILL every time.
trap 'echo "Received stop signal, exiting."; exit 0' TERM INT

: "${SPAMHAUS_DQS_KEY:?Set SPAMHAUS_DQS_KEY, e.g. -e SPAMHAUS_DQS_KEY=your_key}"
: "${ZABBIX_SERVER:?Set ZABBIX_SERVER, e.g. -e ZABBIX_SERVER=10.0.0.5}"
: "${ZABBIX_HOST:?Set ZABBIX_HOST, e.g. -e ZABBIX_HOST=spamhaus-monitor}"
: "${RUN_AT:=09:00}"
: "${RUN_ON_START:=false}"

run_check() {
    echo "=== Spamhaus check starting: $(date '+%Y-%m-%d %H:%M:%S %Z') ==="
    python3 /app/spamhaus_zabbix_check.py /data/ips.txt \
        --statefile /data/state.json \
        --zabbix-server "$ZABBIX_SERVER" \
        --zabbix-host "$ZABBIX_HOST" \
        || echo "Check failed this cycle, will retry at the next scheduled run" >&2
}

# Optional: for testing, set -e RUN_ON_START=true to run once immediately
# before falling into the daily schedule below. Production default is
# false - a restart just re-arms the next 09:00, it does not check now.
if [ "$RUN_ON_START" = "true" ]; then
    echo "RUN_ON_START=true - running one check now before entering the daily schedule"
    run_check
fi

while true; do
    now_epoch=$(date +%s)
    target_epoch=$(date -d "today ${RUN_AT}" +%s)
    if [ "$target_epoch" -le "$now_epoch" ]; then
        target_epoch=$(date -d "tomorrow ${RUN_AT}" +%s)
    fi
    sleep_seconds=$((target_epoch - now_epoch))
    echo "Next check: $(date -d "@${target_epoch}" '+%Y-%m-%d %H:%M:%S %Z') (sleeping ${sleep_seconds}s)"
    sleep "$sleep_seconds"
    run_check
done