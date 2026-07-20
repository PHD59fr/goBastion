# ── Go binary (cross-compiled from build platform, no QEMU) ──────────────────
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS go-builder

ARG TARGETARCH
ARG TARGETOS=linux
ARG VERSION=dev

WORKDIR /app

RUN apk add --no-cache upx

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags "-s -w -X goBastion/version.Version=${VERSION}" \
      -o goBastion ./cmd/goBastion/ && \
    (upx --best --lzma goBastion || upx --best goBastion || upx goBastion || true)

# ── ttyrec (compiled natively for target arch) ───────────────────────────────
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS ttyrec-builder

ARG TTYREC_REF=a1da2fe7c8f33748770768533a33ee7a9988e92c

RUN apk add --no-cache build-base autoconf automake libtool git

RUN git init /tmp/ovh-ttyrec && \
    cd /tmp/ovh-ttyrec && \
    git remote add origin https://github.com/ovh/ovh-ttyrec.git && \
    git fetch --depth 1 origin "$TTYREC_REF" && \
    git checkout --detach FETCH_HEAD && \
    ./configure && \
    make && make install

# ── Final image ──────────────────────────────────────────────────────────────
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache bash gzip openssh sudo jq mosh su-exec && \
    addgroup -S gobastion

RUN sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && sed -i 's/^#SyslogFacility.*/SyslogFacility AUTH/' /etc/ssh/sshd_config \
    && sed -i 's|^Subsystem|#Subsystem|' /etc/ssh/sshd_config \
    && sed -i 's|^#AllowAgentForwarding.*|AllowAgentForwarding no|' /etc/ssh/sshd_config \
    && echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config \
    && sed -i 's|^#PubkeyAuthentication.*|PubkeyAuthentication yes|' /etc/ssh/sshd_config \
    && echo 'Banner /etc/ssh/banner' >> /etc/ssh/sshd_config \
    && echo 'ForceCommand /usr/bin/sudo -n /usr/local/sbin/gobastion-session "$SSH_ORIGINAL_COMMAND"' >> /etc/ssh/sshd_config

COPY --from=go-builder /app/goBastion /app/goBastion
COPY --from=ttyrec-builder /usr/local/bin/ttyrec /usr/local/bin/ttyrec
COPY --from=ttyrec-builder /usr/local/bin/ttyplay /usr/local/bin/ttyplay
COPY banner.txt /etc/ssh/banner
COPY scripts/sudo/gobastion-adduser.sh /usr/local/sbin/gobastion-adduser
COPY scripts/sudo/gobastion-passwd-delete.sh /usr/local/sbin/gobastion-passwd-delete
COPY scripts/sudo/gobastion-deluser.sh /usr/local/sbin/gobastion-deluser
COPY scripts/sudo/gobastion-chown-ssh.sh /usr/local/sbin/gobastion-chown-ssh
COPY scripts/sudo/gobastion-session.sh /usr/local/sbin/gobastion-session
COPY scripts/sudo/gobastion-sync-user.sh /usr/local/sbin/gobastion-sync-user
COPY scripts/sudo/gobastion-sudoers.sh /usr/local/sbin/gobastion-sudoers

RUN chown root:root /app/goBastion && chmod 0755 /app/goBastion && \
    chmod 0755 /usr/local/sbin/gobastion-* && \
    printf '%%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-session *\n' > /etc/sudoers.d/gobastion-session && \
    printf '%%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-sync-user *\n' >> /etc/sudoers.d/gobastion-session && \
    printf 'Defaults!/usr/local/sbin/gobastion-session env_keep += "SSH_CLIENT SSH_CONNECTION SSH_TTY"\n' >> /etc/sudoers.d/gobastion-session && \
    chmod 0440 /etc/sudoers.d/gobastion-session && \
    mkdir -p /var/lib/goBastion /app/ttyrec && \
    chown root:gobastion /var/lib/goBastion /app/ttyrec && \
    chmod 2770 /var/lib/goBastion /app/ttyrec && \
    touch /goBastion.log && chown root:gobastion /goBastion.log && chmod 0620 /goBastion.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
