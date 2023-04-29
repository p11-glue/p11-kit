#!/bin/sh

set -ex

mkdir "$GITHUB_WORKSPACE/$BUILDDIR"
mkdir "$GITHUB_WORKSPACE/$INSTALLDIR"
mkdir -p "$GITHUB_WORKSPACE/$INSTALLDIR/etc/pki/ca-trust-source"
mkdir -p "$GITHUB_WORKSPACE/$INSTALLDIR/share/pki/ca-trust-source"

if test $(id -u) -eq 0; then
    case "$RUNNER_OS" in
	Linux)
	    useradd -m "$RUNUSER"
	    chown -R "$RUNUSER" "$GITHUB_WORKSPACE/$BUILDDIR"
	    # This is necessary to put p11-kit.pot in $(srcdir)
	    chown -R "$RUNUSER" "$GITHUB_WORKSPACE/po"
	    ;;
	*)
	    echo "Unsupported OS: $RUNNER_OS" 1>&2
	    exit 1
	    ;;
    esac
fi
