#!/bin/sh
# Enrol once (the credential is kept under /var/lib/sentinel), then watch.
set -eu
STATE=/var/lib/sentinel
if [ ! -s "$STATE/agent.json" ]; then
  : "${SENTINEL_SERVER:?Set SENTINEL_SERVER}"
  : "${SENTINEL_ENROLL_KEY:?Set SENTINEL_ENROLL_KEY}"
  /opt/sentinel/garrett --state-dir "$STATE" enroll --server "$SENTINEL_SERVER" ${SENTINEL_LABEL:+--label "$SENTINEL_LABEL"} --mode "${SENTINEL_MODE:-kill}"
fi
# A container is brought up to date by a new image, never from inside.
exec /opt/sentinel/garrett --state-dir "$STATE" run --update off
