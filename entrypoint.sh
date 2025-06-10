#!/bin/sh
/bin/busybox syslogd -n -O /goBastion.log &
/app/goBastion -restore
/usr/sbin/sshd -D &
tail -f /goBastion.log
