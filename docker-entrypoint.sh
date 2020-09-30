#!/usr/bin/env sh

main_cmd=phishthis.py

if [ "${1:0:1}" = '-' ] || [ "$1" = "$main_cmd" ]; then
  if [ "$1" = "$main_cmd" ]; then
    shift
  fi
  [ "$GMAIL_USER" ] && set -- --username "$GMAIL_USER" "$@"
  [ "$GMAIL_APP_PASSWORD" ] && set -- --password "$GMAIL_APP_PASSWORD" "$@"
  [ "$FORWARD_ADDRESS" ] && set -- --forward "$FORWARD_ADDRESS" "$@"
	set -- $main_cmd "$@"
fi

exec "$@"
