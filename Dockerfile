# ── Go binary (cross-compiled from build platform, no QEMU) ──────────────────
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:26402d86be3d72e6a9410afa0108f03529f51f0c1b5eb7f503d0bc44cc7857ac AS go-builder

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
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /app/db-worker ./cmd/dbworker/ && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go test -c -o /app/dbsandbox.test ./internal/dbsandbox && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go test -c -o /app/policy.test ./internal/models && \
    (upx --best --lzma goBastion || upx --best goBastion || upx goBastion || true)

# ── ttyrec (compiled natively for target arch) ───────────────────────────────
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS ttyrec-builder

ARG TTYREC_REF=a1da2fe7c8f33748770768533a33ee7a9988e92c

RUN apk add --no-cache build-base autoconf automake libtool git upx

RUN git init /tmp/ovh-ttyrec && \
    cd /tmp/ovh-ttyrec && \
    git remote add origin https://github.com/ovh/ovh-ttyrec.git && \
    git fetch --depth 1 origin "$TTYREC_REF" && \
    git checkout --detach FETCH_HEAD && \
    ./configure && \
    make && make install && \
    strip /usr/local/bin/ttyrec /usr/local/bin/ttyplay && \
    (upx --best --lzma /usr/local/bin/ttyrec /usr/local/bin/ttyplay || \
     upx --best /usr/local/bin/ttyrec /usr/local/bin/ttyplay || \
     upx /usr/local/bin/ttyrec /usr/local/bin/ttyplay || true)

FROM alpine:3.22 AS db-root
RUN apk add --no-cache mariadb-client postgresql-client redis iproute2 ca-certificates && mkdir -p /home /tmp /proc /dev && touch /etc/db-hosts-template && rm -rf /var/cache/apk/*
COPY --from=go-builder /app/db-worker /bin/db-worker

# ── Runtime common image ─────────────────────────────────────────────────────
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS runtime-common

RUN apk add --no-cache \
      nsjail=3.4-r7 \
      bash \
      gzip \
      jq \
      mariadb-client \
      openssh \
      postgresql-client \
      redis \
      su-exec \
      sudo && \
    addgroup -S gobastion && \
    if ! command -v mysql >/dev/null 2>&1 && command -v mariadb >/dev/null 2>&1; then \
      ln -s /usr/bin/mariadb /usr/bin/mysql; \
    fi && \
    command -v mysql >/dev/null 2>&1 && \
    command -v psql >/dev/null 2>&1 && \
    command -v redis-cli >/dev/null 2>&1

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

RUN mkdir -p /usr/local/sbin && ln -s /usr/bin/nsjail /usr/local/sbin/nsjail
COPY --from=db-root / /opt/gobastion-db-root/
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/etc/hosts
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/dev/null
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/dev/urandom
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/dev/zero
COPY scripts/sudo/gobastion-db-session.sh /usr/local/sbin/gobastion-db-session
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
    printf '%%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-db-session *\n' >> /etc/sudoers.d/gobastion-session && \
    printf 'Defaults!/usr/local/sbin/gobastion-db-session env_keep += "SSH_CLIENT SSH_CONNECTION SSH_TTY"\n' >> /etc/sudoers.d/gobastion-session && \
    chmod 0440 /etc/sudoers.d/gobastion-session && \
    mkdir -p /var/lib/goBastion /app/ttyrec && \
    chown root:gobastion /var/lib/goBastion /app/ttyrec && \
    chmod 2770 /var/lib/goBastion /app/ttyrec && \
    touch /goBastion.log && chown root:gobastion /goBastion.log && chmod 0620 /goBastion.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]

# ── Legacy full image target ───────────────────────────────────────────────
FROM runtime-common AS final-full

# Legacy image target retained; local Mosh is deliberately unavailable.

# ── Disposable integration test image ───────────────────────────────────────
FROM runtime-common AS isolation-test
RUN apk add --no-cache postgresql mariadb mariadb-client openssl && mkdir -p /run/mysqld
COPY --from=go-builder /app/dbsandbox.test /dbsandbox.test
COPY --from=go-builder /app/dbsandbox.test /opt/gobastion-db-root/bin/caps-test
COPY --from=go-builder /app/policy.test /policy.test
COPY scripts/test-db-isolation.sh /test-db-isolation.sh
COPY scripts/test-db-supervisor.sh /test-db-supervisor.sh
ENTRYPOINT ["/bin/sh", "/test-db-isolation.sh"]

# ── Default image ──────────────────────────────────────────────────────────
FROM runtime-common AS final
