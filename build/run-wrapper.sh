#!/bin/sh

set -ex

if test $(id -u) -eq 0; then
    case "$RUNNER_OS" in
	Linux)
	    exec runuser -u "$RUNUSER" -- "$@"
	    ;;
	*)
	    echo "Unsupported OS: $RUNNER_OS" 1>&2
	    exit 1
	    ;;
    esac
else
    exec "$@"
fi
