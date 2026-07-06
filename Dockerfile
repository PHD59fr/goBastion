FROM golang:1.26.0-alpine3.22 AS builder

WORKDIR /app

COPY . .

RUN apk upgrade --no-cache && \
    apk add --no-cache upx build-base autoconf automake libtool wget git && \
    go mod tidy && \
    CGO_ENABLED=0 go build -o goBastion ./cmd/goBastion/ && \
    upx --best --lzma goBastion

RUN git clone https://github.com/ovh/ovh-ttyrec.git /tmp/ovh-ttyrec && \
    cd /tmp/ovh-ttyrec && \
    ./configure && \
    make && make install

FROM alpine:3.22

RUN apk upgrade --no-cache && \
    apk add --no-cache bash gzip openssh sudo jq mosh

RUN sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && sed -i 's/^#SyslogFacility.*/SyslogFacility AUTH/' /etc/ssh/sshd_config \
    && sed -i 's|^Subsystem|#Subsystem|' /etc/ssh/sshd_config \
    && sed -i 's|^#AllowAgentForwarding.*|AllowAgentForwarding no|' /etc/ssh/sshd_config \
    && echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config \
    && sed -i 's|^#PubkeyAuthentication.*|PubkeyAuthentication yes|' /etc/ssh/sshd_config \
    && echo 'Banner /etc/ssh/banner' >> /etc/ssh/sshd_config \
    && echo 'ForceCommand /app/goBastion "$SSH_ORIGINAL_COMMAND"' >> /etc/ssh/sshd_config

COPY --from=builder /app/goBastion /app/goBastion
COPY --from=builder /usr/local/bin/ttyrec /usr/local/bin/ttyrec
COPY --from=builder /usr/local/bin/ttyplay /usr/local/bin/ttyplay
COPY banner.txt /etc/ssh/banner
COPY scripts/sudo/gobastion-adduser.sh /usr/local/sbin/gobastion-adduser
COPY scripts/sudo/gobastion-passwd-delete.sh /usr/local/sbin/gobastion-passwd-delete
COPY scripts/sudo/gobastion-deluser.sh /usr/local/sbin/gobastion-deluser
COPY scripts/sudo/gobastion-chown-ssh.sh /usr/local/sbin/gobastion-chown-ssh

RUN chown root:root /app/goBastion
RUN chmod u+s /app/goBastion
RUN chmod 755 /usr/local/sbin/gobastion-adduser /usr/local/sbin/gobastion-passwd-delete /usr/local/sbin/gobastion-deluser /usr/local/sbin/gobastion-chown-ssh
RUN touch /goBastion.log && chmod 640 /goBastion.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
