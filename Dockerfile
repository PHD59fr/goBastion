# ── Go binary (cross-compiled from build platform, no QEMU) ──────────────────
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.23 AS go-builder

ARG TARGETARCH
ARG TARGETOS=linux

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags "-s -w -X goBastion/version.Version=$(git describe --tags --always 2>/dev/null)" \
      -o goBastion ./cmd/goBastion/ && \
    (upx --best --lzma goBastion || upx --best goBastion || upx goBastion || true)

# ── ttyrec (compiled natively for target arch) ───────────────────────────────
FROM alpine:3.22 AS ttyrec-builder

RUN apk upgrade --no-cache && \
    apk add --no-cache build-base autoconf automake libtool wget git

RUN git clone https://github.com/ovh/ovh-ttyrec.git /tmp/ovh-ttyrec && \
    cd /tmp/ovh-ttyrec && \
    ./configure && \
    make && make install

# ── Final image ──────────────────────────────────────────────────────────────
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

COPY --from=go-builder /app/goBastion /app/goBastion
COPY --from=ttyrec-builder /usr/local/bin/ttyrec /usr/local/bin/ttyrec
COPY --from=ttyrec-builder /usr/local/bin/ttyplay /usr/local/bin/ttyplay
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
