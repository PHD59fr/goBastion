#!/bin/sh

/bin/busybox syslogd -n -O /goBastion.log &

if [ -x /var/lib/goBastion/bastion.db ]; then
    /app/goBastion -restore
fi

/usr/sbin/sshd -D &

tail -f /goBastion.log
