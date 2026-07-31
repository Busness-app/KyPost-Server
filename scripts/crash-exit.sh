#!/bin/sh
# supervisord event listener: bring the container DOWN when a supervised program
# gives up, instead of leaving PID 1 healthy in front of a dead service.
#
# supervisord's default startretries is 3, which marks a program FATAL and then
# keeps running happily — the container stays "running" while serving nothing,
# and Docker's restart policies never fire because they react to a container
# EXITING, never to a healthcheck failing.
#
# The previous answer to that was startretries=1000000, which trades an invisible
# death for an invisible hot loop: supervisord does not back off between restart
# attempts, so a program that exits immediately (bad config, a corrupt state
# file, a panic on boot) is restarted as fast as the machine allows, forever,
# burning a core inside a container whose whole premise is CPU contention with a
# local LLM. Nothing recovers it and nothing exits.
#
# So: retry a bounded number of times for the transient case that motivated the
# large number (a dependency that is not ready yet — the volume, Ollama, DNS),
# then exit and let `restart: unless-stopped` restart the whole container. That
# path DOES have backoff, and a container restart loop is visible in
# `docker ps` and to any orchestrator.
#
# Reads the supervisor event protocol on stdin and answers on stdout, so it must
# print nothing else to stdout. Diagnostics go to stderr, which supervisord
# captures into this program's own log.
set -eu

printf 'READY\n'

while IFS= read -r header; do
	# The header is "ver:3.0 server:supervisor serial:21 ... len:56"; the payload
	# that follows is exactly len bytes and is not newline-terminated.
	length=$(printf '%s' "$header" | tr ' ' '\n' | sed -n 's/^len://p')
	payload=''
	if [ -n "${length:-}" ] && [ "$length" -gt 0 ] 2>/dev/null; then
		payload=$(dd bs=1 count="$length" 2>/dev/null)
	fi

	printf '%s\n' "supervisord: program entered FATAL, stopping the container so it can be restarted: $payload" >&2

	# Acknowledge before exiting, so supervisord does not log a protocol error on
	# top of the real one.
	printf 'RESULT 2\nOK'

	# SIGTERM to PID 1 (supervisord) is a graceful shutdown: it stops the other
	# programs, then exits, and the container exits with it.
	kill -TERM 1
	exit 0
done
