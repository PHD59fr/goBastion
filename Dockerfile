FROM golang:1.24-alpine as builder

WORKDIR /app

COPY . .

RUN apk add --no-cache upx build-base autoconf automake libtool wget git && \
    CGO_ENABLED=0 go build -o goBastion && \
    upx --best --lzma goBastion

RUN git clone https://github.com/ovh/ovh-ttyrec.git /tmp/ovh-ttyrec && \
    cd /tmp/ovh-ttyrec && \
    ./configure && \
    make && make install

FROM alpine:latest

RUN apk add --no-cache openssh bash sudo

RUN sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && sed -i 's/^#SyslogFacility.*/SyslogFacility AUTH/' /etc/ssh/sshd_config \
    && sed -i 's|^Subsystem sftp.*|#Subsystem sftp internal-sftp|' /etc/ssh/sshd_config \
    && echo 'ForceCommand /app/goBastion "$SSH_ORIGINAL_COMMAND"' >> /etc/ssh/sshd_config

RUN ssh-keygen -A

COPY --from=builder /app/goBastion /app/goBastion
COPY --from=builder /usr/local/bin/ttyrec /usr/local/bin/ttyrec

RUN chown root:root /app/goBastion
RUN chmod u+s /app/goBastion

EXPOSE 22

CMD /bin/busybox syslogd -n -O /dev/stdout & /app/goBastion -restore ; /usr/sbin/sshd -D
