#!/bin/sh
# after_script helper: Travis archives job logs asynchronously, so a log read
# right after the job ends can stop before the test results. Keep the job open
# (printing a heartbeat, so Travis's 10-minute no-output watchdog never fires)
# until this job's public log contains Gradle's final build line, capped at
# 30 minutes. after_script cannot change the build result.
MAX=1800
elapsed=0
URL="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
PATTERN='BUILD (SUCCESSFUL|FAILED) in [0-9]'
while [ "$elapsed" -lt "$MAX" ]; do
    if curl -fsSL "$URL" 2>/dev/null | grep -Eq "$PATTERN"; then
        echo "wait-for-log: build result archived after ${elapsed}s"
        exit 0
    fi
    echo "wait-for-log: waiting for log archive... (${elapsed}s)"
    sleep 20
    elapsed=$((elapsed + 20))
done
echo "wait-for-log: gave up after ${MAX}s"
exit 0
