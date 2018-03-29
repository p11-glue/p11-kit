#/bin/sh

: ${WINE=wine}
export WINE

case "$1" in
	*.sh)
		exec $1
	;;
	*)
		${WINE} $1 | tr -d '\r'
	;;
esac
