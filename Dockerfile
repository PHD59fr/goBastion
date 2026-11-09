# ── Go binary (cross-compiled from build platform, no QEMU) ──────────────────
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS go-source

ARG TARGETARCH
ARG TARGETOS=linux

ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH

WORKDIR /app


COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY version/ ./version/

FROM go-source AS go-builder
ARG VERSION=dev
# UPX compression is enabled by default ("all"). It reduces image size but
# removes Go build metadata (so `go version -m` and Go-binary SBOM cataloging
# no longer see module information) and adds startup decompression cost.
# "cold" packs only offline/daemon helpers; "off" disables compression. "all"
# also packs goBastion and db-worker, which are invoked on every SSH
# authentication and database session and therefore pay the decompression cost
# on each invocation.
ARG UPX_MODE=all

RUN --mount=type=cache,target=/root/.cache/go-build \
    go build \
      -ldflags "-s -w -X goBastion/version.Version=${VERSION}" \
      -o goBastion ./cmd/goBastion/ && \
    go build -ldflags "-s -w" -o /app/db-worker ./cmd/dbworker/ && \
    go build -ldflags "-s -w" -o /app/secret-migrate ./cmd/secret-migrate/ && \
    go build -ldflags "-s -w" -o /app/observability ./cmd/observability/ && \
    go build -ldflags "-s -w" -o /app/recording-admin ./cmd/recording-admin/

RUN set -eu; \
    case "$UPX_MODE" in \
      off) exit 0 ;; \
      cold) bins="/app/secret-migrate /app/observability /app/recording-admin" ;; \
      all) bins="/app/goBastion /app/db-worker /app/secret-migrate /app/observability /app/recording-admin" ;; \
      *) echo "UPX_MODE must be off, cold or all" >&2; exit 1 ;; \
    esac; \
    apk add --no-cache upx; \
    for bin in $bins; do \
      upx --best --lzma "$bin" || upx --best "$bin" || upx "$bin" || upx -t "$bin" >/dev/null; \
    done

# Only the integration target needs test executables.
FROM go-source AS go-test-builder
RUN --mount=type=cache,target=/root/.cache/go-build \
    go test -c -o /app/dbsandbox.test ./internal/dbsandbox && \
    go test -c -o /app/policy.test ./internal/models && \
    go test -c -o /app/session.test ./internal/session && \
    go test -c -o /app/recording.test ./internal/recording

# ── ttyrec (compiled natively for target arch) ───────────────────────────────
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS ttyrec-builder

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

# Extract only redis-cli: the full redis package includes the server and its
# CVEs, while the bastion only needs the client.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS redis-client
RUN apk upgrade --no-cache && apk add --no-cache redis && \
    install -D -m 0755 /usr/bin/redis-cli /out/redis-cli

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS db-root
# The jail needs interactive clients, not MariaDB maintenance tools or a Redis
# server. Upgrade inherited base packages and prune before copying this rootfs
# into the runtime image.
RUN apk upgrade --no-cache && \
    apk add --no-cache mariadb-client postgresql-client iproute2 ca-certificates && \
    find /usr/bin -maxdepth 1 \
      \( -name 'mariadb-*' -o -name 'mysql*' -o -name 'myisam_ftdump' \) \
      ! -name mysql -delete && \
    mkdir -p /home /tmp /proc /dev && \
    touch /etc/db-hosts-template
COPY --from=go-builder --chown=0:0 --chmod=0755 /app/db-worker /bin/db-worker
COPY --from=redis-client --chmod=0755 /out/redis-cli /usr/bin/redis-cli

# ── Runtime common image ─────────────────────────────────────────────────────
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS runtime-common

# Upgrade inherited base packages before installing dependencies; apk add does
# not replace already-installed base packages with newer branch fixes.
RUN apk upgrade --no-cache && \
    apk add --no-cache \
      nsjail=3.4-r7 \
      bash \
      gzip \
      jq \
      mariadb-client \
      openssh \
      postgresql-client \
      su-exec \
      sudo && \
    addgroup -S gobastion && \
    addgroup -S gobastion-auditors && \
    if ! command -v mysql >/dev/null 2>&1 && command -v mariadb >/dev/null 2>&1; then \
      ln -s /usr/bin/mariadb /usr/bin/mysql; \
    fi && \
    command -v mysql >/dev/null 2>&1 && \
    command -v psql >/dev/null 2>&1

COPY scripts/configure-sshd.sh /tmp/configure-sshd.sh
RUN sh /tmp/configure-sshd.sh && rm /tmp/configure-sshd.sh

RUN mkdir -p /usr/local/sbin && ln -s /usr/bin/nsjail /usr/local/sbin/nsjail
COPY --from=db-root / /opt/gobastion-db-root/
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/etc/hosts
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/dev/null
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/dev/urandom
COPY --from=db-root /etc/db-hosts-template /opt/gobastion-db-root/dev/zero
COPY --chmod=0755 scripts/sudo/gobastion-db-session.sh /usr/local/sbin/gobastion-db-session
COPY --from=go-builder --chown=0:0 --chmod=0755 /app/goBastion /app/goBastion
COPY --from=go-builder --chown=0:0 --chmod=0700 /app/secret-migrate /app/secret-migrate
COPY --from=go-builder --chown=0:0 --chmod=0700 /app/observability /app/observability
COPY --from=go-builder --chown=0:0 --chmod=0700 /app/recording-admin /app/recording-admin
COPY --from=ttyrec-builder /usr/local/bin/ttyrec /usr/local/bin/ttyrec
COPY --from=ttyrec-builder /usr/local/bin/ttyplay /usr/local/bin/ttyplay
COPY --from=redis-client --chmod=0755 /out/redis-cli /usr/bin/redis-cli
RUN redis-cli --version >/dev/null 2>&1
COPY banner.txt /etc/ssh/banner
COPY --chmod=0755 scripts/sudo/gobastion-adduser.sh /usr/local/sbin/gobastion-adduser
COPY --chmod=0755 scripts/sudo/gobastion-passwd-delete.sh /usr/local/sbin/gobastion-passwd-delete
COPY --chmod=0755 scripts/sudo/gobastion-deluser.sh /usr/local/sbin/gobastion-deluser
COPY --chmod=0755 scripts/sudo/gobastion-chown-ssh.sh /usr/local/sbin/gobastion-chown-ssh
COPY --chmod=0755 scripts/sudo/gobastion-session.sh /usr/local/sbin/gobastion-session
COPY --chmod=0755 scripts/sudo/gobastion-sync-user.sh /usr/local/sbin/gobastion-sync-user
COPY --chmod=0755 scripts/sudo/gobastion-sudoers.sh /usr/local/sbin/gobastion-sudoers

RUN printf '%%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-session *\n' > /etc/sudoers.d/gobastion-session && \
    printf '%%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-sync-user *\n' >> /etc/sudoers.d/gobastion-session && \
    printf 'Defaults!/usr/local/sbin/gobastion-session env_keep += "SSH_CLIENT SSH_CONNECTION SSH_TTY"\n' >> /etc/sudoers.d/gobastion-session && \
    printf '%%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-db-session *\n' >> /etc/sudoers.d/gobastion-session && \
    printf 'Defaults!/usr/local/sbin/gobastion-db-session env_keep += "SSH_CLIENT SSH_CONNECTION SSH_TTY"\n' >> /etc/sudoers.d/gobastion-session && \
    chmod 0440 /etc/sudoers.d/gobastion-session && \
    mkdir -p /var/lib/goBastion /app/ttyrec && \
    chown root:gobastion /var/lib/goBastion /app/ttyrec && \
    chmod 2770 /var/lib/goBastion && chmod 0751 /app/ttyrec && \
    touch /goBastion.log && chown root:gobastion /goBastion.log && chmod 0620 /goBastion.log

COPY --chmod=0755 entrypoint.sh /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]

# ── Legacy full image target ───────────────────────────────────────────────
FROM runtime-common AS final-full

# Legacy image target retained; local Mosh is deliberately unavailable.

# ── Disposable integration test image ───────────────────────────────────────
FROM runtime-common AS isolation-test
RUN apk add --no-cache postgresql mariadb mariadb-client openssl && mkdir -p /run/mysqld
COPY --from=go-test-builder /app/dbsandbox.test /dbsandbox.test
COPY --from=go-test-builder /app/dbsandbox.test /opt/gobastion-db-root/bin/caps-test
COPY --from=go-test-builder /app/policy.test /policy.test
COPY --from=go-test-builder /app/session.test /session.test
COPY --from=go-test-builder /app/recording.test /recording.test
COPY scripts/test-db-isolation.sh /test-db-isolation.sh
COPY scripts/test-db-supervisor.sh /test-db-supervisor.sh
ENTRYPOINT ["/bin/sh", "/test-db-isolation.sh"]

# ── Default image ──────────────────────────────────────────────────────────
FROM runtime-common AS final
