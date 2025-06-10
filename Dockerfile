FROM golang:1.24-alpine AS builder

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

RUN apk add --no-cache bash gzip openssh sudo busybox

RUN sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && sed -i 's/^#SyslogFacility.*/SyslogFacility AUTH/' /etc/ssh/sshd_config \
    && sed -i 's|^Subsystem sftp.*|#Subsystem sftp internal-sftp|' /etc/ssh/sshd_config \
    && echo 'ForceCommand /app/goBastion "$SSH_ORIGINAL_COMMAND"' >> /etc/ssh/sshd_config

COPY --from=builder /app/goBastion /app/goBastion
COPY --from=builder /usr/local/bin/ttyrec /usr/local/bin/ttyrec
COPY --from=builder /usr/local/bin/ttyplay /usr/local/bin/ttyplay

RUN chown root:root /app/goBastion
RUN chmod u+s /app/goBastion
RUN touch /goBastion.log && chmod 644 /goBastion.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]