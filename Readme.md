# 🚀 **goBastion**

**goBastion** is a tool for managing SSH access, user roles, and keys on a bastion host. The project is currently under active development, and contributions are welcome!

🔗 **GitHub Repository**: [https://github.com/phd59fr/goBastion](https://github.com/phd59fr/goBastion)

🐳 **Docker Hub Image**: [https://hub.docker.com/r/phd59fr/gobastion](https://hub.docker.com/r/phd59fr/gobastion)

---

## ✨ **Key Concept - Database as the Source of Truth**

In **goBastion**, **the database is the single source of truth** for SSH keys and access management. This means that the system always reflects the state of the database. Any key or access added manually to the system without passing through the bastion will be **automatically removed** to maintain consistency.

### How it works:

* **Key Addition**:
  When a user adds an SSH key, it is first validated and stored in the database. The bastion then automatically synchronizes the database with the system, adding the key to the appropriate location.

* **Automatic Synchronization**:
  The bastion enforces the database state every **5 minutes** automatically. If it finds an SSH key, user, or host entry not in the database, it is immediately corrected to ensure security and consistency. The `--sync` flag allows triggering this on demand.

### **Advantages of this Approach**

* **Centralized Control**: All modifications go through the bastion, ensuring tight access management.
* **Enhanced Security**: Unauthorized keys cannot remain on the system.
* **State Consistency**: The system always mirrors the database state.
* **Audit and Traceability**: Every change is recorded in the database.
* **Fully Automated Management**: No need for manual checks; synchronization handles everything.
* **Easy Exportability**: The system can be deployed on a new container effortlessly. Since the database is the source of truth, replicating it with synchronization scripts provides a functional bastion on a new instance.

---

## 🔍 **Features Overview**

### 👤 **Self-Commands (Manage Your Own Account)**

| Command                          | Description                                                                  |
|----------------------------------|------------------------------------------------------------------------------|
| 🔑 `selfListIngressKeys`         | List your ingress SSH keys (keys for connecting to the bastion).             |
| ➕ `selfAddIngressKey`            | Add a new ingress SSH key (optional expiry).                                 |
| ❌ `selfDelIngressKey`            | Delete an ingress SSH key.                                                   |
| 🔑 `selfListEgressKeys`          | List your egress SSH keys (keys for connecting from the bastion to servers). |
| 🔑 `selfGenerateEgressKey`       | Generate a new egress SSH key.                                               |
| 📋 `selfListAccesses`            | List your personal server accesses.                                          |
| ➕ `selfAddAccess`                | Add access to a personal server (supports IP restriction, TTL, protocol).    |
| ❌ `selfDelAccess`                | Remove access to a personal server.                                          |
| 📋 `selfListAliases`             | List your personal SSH aliases.                                              |
| ➕ `selfAddAlias`                 | Add a personal SSH alias.                                                    |
| ❌ `selfDelAlias`                 | Delete a personal SSH alias.                                                 |
| ❌ `selfRemoveHostFromKnownHosts` | Remove a host from your known\_hosts file.                                   |
| 🔄 `selfReplaceKnownHost`        | Trust a new host key after it changed (TOFU reset).                          |
| 🔐 `selfSetupTOTP`               | Enable TOTP two-factor authentication (generates QR/OTP URI).                |
| 🔐 `selfDisableTOTP`             | Disable TOTP two-factor authentication.                                      |
| 🔑 `selfSetPassword`             | Set a password second factor (MFA). Required at every login if set.          |
| 🔑 `selfChangePassword`          | Change your password second factor.                                          |
| 🔑 `selfDisablePassword`         | Disable password second factor (MFA).                                        |
| 🛡️ `selfAddIngressKeyPIV`       | Add a PIV/YubiKey hardware-attested ingress key.                             |
| 🔐 `selfGenerateBackupCodes`     | Generate TOTP backup codes (single-use recovery codes).                     |
| 🔐 `selfShowBackupCodeCount`     | Show remaining backup codes count.                                          |

---

### 🦸 **Admin Commands (Manage Other Accounts)**

| Command                     | Description                                           |
|-----------------------------|-------------------------------------------------------|
| 📋 `accountList`            | List all user accounts.                               |
| ℹ️ `accountInfo`            | Show detailed information about a user account.       |
| ➕ `accountCreate`           | Create a new user account (supports `--osh-only` and `--superowner`). |
| ❌ `accountDelete`           | Delete a user account.                                |
| ✏️ `accountModify`          | Modify a user account (role, `--oshOnly`, `--superOwner`). Cannot demote the last remaining admin. |
| 🔑 `accountListIngressKeys` | List the ingress SSH keys of a user.                  |
| 🔑 `accountListEgressKeys`  | List the egress SSH keys of a user.                   |
| 📋 `accountListAccess`      | List all server accesses of a user.                                          |
| ➕ `accountAddAccess`        | Grant a user access to a server (supports IP restriction, TTL, protocol).    |
| ❌ `accountDelAccess`        | Remove a user's access to a server.                                          |
| 📋 `whoHasAccessTo`         | Show all users with access to a specific server (supports CIDR).             |
| 🔐 `accountDisableTOTP`    | Disable TOTP two-factor authentication for a user.                           |
| 🔑 `accountSetPassword`    | *(admin)* Set or clear a user's password second factor.                       |
| 🛡️ `pivAddTrustAnchor`     | Register a Yubico PIV CA certificate as a trust anchor.                      |
| 📋 `pivListTrustAnchors`    | List all registered PIV trust anchor CAs.                                    |
| ❌ `pivRemoveTrustAnchor`   | Remove a PIV trust anchor CA.                                                |

---

### 🚧 **Restricted Operations**

| Command                     | Description                                           |
|----------------------------|-------------------------------------------------------|
| ➕ `realmCreate`            | Create a trusted realm (`--realm`, `--bastion`, `--port`, `--from`, `--public-key`). |
| 📋 `realmList`              | List configured trusted realms.                       |
| ℹ️ `realmInfo`              | Show details for a trusted realm.                     |
| ❌ `realmDelete`            | Delete a trusted realm.                               |
| ➕ `restrictedGrantAdd`     | Grant a restricted command to a specific user.        |
| ❌ `restrictedGrantDel`     | Remove a restricted command grant from a user.        |
| 📋 `restrictedGrantList`    | List restricted command grants (all or per user).     |

---

### 👥 **Group Management**

| Command                     | Description                                       |
|-----------------------------|---------------------------------------------------|
| ℹ️ `groupInfo`              | Show detailed information about a group.          |
| 📋 `groupList`              | List all groups.                                  |
| ➕ `groupCreate`             | Create a new group.                               |
| ❌ `groupDelete`             | Delete a group.                                   |
| ➕ `groupAddMember`          | Add a user to a group.                            |
| ❌ `groupDelMember`          | Remove a user from a group.                       |
| 🔑 `groupGenerateEgressKey` | Generate a new egress SSH key for the group.      |
| 🔑 `groupListEgressKeys`    | List all egress SSH keys associated with a group. |
| 📋 `groupListAccesses`      | List all accesses assigned to a group.            |
| ➕ `groupAddAccess`          | Grant access to a group (supports protocol restriction and optional `--guest` scope). The optional TCP connectivity check is restricted to private/reserved IP ranges to prevent network scanning. Use `--force` to skip. |
| ❌ `groupDelAccess`          | Remove access from a group.                       |
| 🔐 `groupSetMFA`            | Enable or disable JIT MFA requirement for a group (owner/admin only).       |
| ➕ `groupAddAlias`           | Add a group SSH alias.                            |
| ❌ `groupDelAlias`           | Delete a group SSH alias.                         |
| 📋 `groupListAliases`       | List all group SSH aliases.                       |

---

### 🔐 **MFA / TOTP (Two-Factor Authentication)**

goBastion supports multiple second-factor authentication methods that stack: password, TOTP, and JIT MFA per group.

#### TOTP

| Command               | Description                                                            |
|-----------------------|------------------------------------------------------------------------|
| `selfSetupTOTP`       | Generate a TOTP secret and display the QR/OTP URI to add to your authenticator app. |
| `selfDisableTOTP`     | Disable TOTP for your own account.                                     |
| `accountDisableTOTP`  | *(admin)* Disable TOTP for any user account.                           |

Once TOTP is enabled, the bastion will prompt for a 6-digit code at every interactive or passthrough login.

#### Backup Codes

Backup codes are single-use recovery codes that can be used instead of a TOTP code when you lose access to your authenticator app.

| Command                     | Description                                              |
|-----------------------------|----------------------------------------------------------|
| `selfGenerateBackupCodes`   | Generate 10 new backup codes. Previous codes are invalidated. |
| `selfShowBackupCodeCount`   | Show how many backup codes remain unused.                |

- Each code can only be used once and is removed after use.
- Backup codes are accepted in the same prompt as TOTP codes (`Enter TOTP code (or backup code):`).
- Generating new codes invalidates all previous codes.

#### Password Second Factor

| Command                  | Description                                                               |
|--------------------------|---------------------------------------------------------------------------|
| `selfSetPassword`        | Set a bcrypt-hashed password as a second factor. Required at every login. |
| `selfChangePassword`     | Change your password second factor (requires current password).           |
| `accountSetPassword`     | *(admin)* Set or clear a user's password second factor.                   |

Password MFA is independent of TOTP — both can be active simultaneously.

#### JIT MFA (per-group)

When a group has JIT MFA enabled via `groupSetMFA`, any user connecting via that group must pass a TOTP challenge at connection time, even if global TOTP is not enabled for their account. The user must have a TOTP secret configured (`selfSetupTOTP`) for this to work.

| Command         | Description                                              |
|-----------------|----------------------------------------------------------|
| `groupSetMFA`   | *(owner/admin)* Enable or disable JIT MFA for a group.                   |

---

### 📡 **SCP / SFTP / rsync Passthrough**

goBastion supports two passthrough modes depending on whether you need to use the bastion's egress key (recommended) or your own key on the target.

#### Mode 1 — sftp-session (recommended, uses bastion's egress key)

goBastion acts as a minimal SSH server and connects to the target with its own egress key. **Your local key does not need to be on the target server.**

```ssh-config
Host my-server
    HostName 192.168.1.10
    User myuser
    ProxyCommand ssh -p 2222 -- bastion_user@bastion "sftp-session myuser@%h:%p"
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

> `StrictHostKeyChecking no` is required because goBastion generates an ephemeral host key for the fake SSH server on each connection.

Then use sftp normally:
```sh
sftp my-server
```

#### Mode 2 — TCP proxy (requires your key on the target)

Passes `-W %h:%p` **as a quoted string** after `--` so glibc does not treat it as a native SSH flag:

```ssh-config
Host my-server
    HostName 192.168.1.10
    User myuser
    ProxyCommand ssh -p 2222 -- bastion_user@bastion "-W %h:%p"
```

> **Why `--` before the hostname?**  
> On Linux (glibc), `ssh -W host:port` opens a raw `direct-tcpip` channel that bypasses goBastion's access controls — and is refused by the bastion's sshd.  
> The `--` tells SSH's option parser to stop processing flags, so `-W %h:%p` becomes the **remote exec command** forwarded to goBastion, which handles it as a controlled TCP proxy via `parseTCPProxyRequest`.

This enables:
- `scp file.txt user@my-server:/path/`
- `sftp user@my-server`
- `rsync -avz ./dir/ user@my-server:/path/`

All passthrough connections are subject to the same access control rules as interactive SSH sessions.

#### Protocol Restriction

Access entries can be restricted to a specific transfer protocol using the `--protocol` flag on `selfAddAccess`, `accountAddAccess`, and `groupAddAccess`:

| Value         | Meaning                                     |
|---------------|---------------------------------------------|
| `ssh`         | All protocols (default, backwards-compatible) |
| `scpupload`   | SCP upload only (`scp -t`)                  |
| `scpdownload` | SCP download only (`scp -f`)                |
| `sftp`        | SFTP only                                   |
| `rsync`       | rsync only                                  |

Example: grant a user rsync-only access to a backup server:
```
groupAddAccess --group backups --server 10.0.0.5 --username backup --protocol rsync
```

---

### ⏱️ **Access TTL and IP Restriction**

Every access entry (`selfAddAccess`, `accountAddAccess`, `groupAddAccess`) supports two optional constraints:

| Flag | Description |
|------|-------------|
| `--ttl <days>` | Access expires automatically after N days. Omit for permanent access. |
| `--from <CIDRs>` | Restrict access to specific source IP ranges (comma-separated, e.g. `10.0.0.0/8,192.168.1.0/24`). Omit to allow all IPs. |

For `groupAddAccess`, you can also add `--guest` to explicitly allow users with the `guest` role
to use that specific access entry. Without `--guest`, guest members are denied for that entry.

Both constraints are enforced at connection time - expired or out-of-range connections are denied.
The `Expires` and `From` columns appear in all `listAccesses` outputs.

> **Security note (IP restrictions):** If a `--from` CIDR restriction is set on an access entry
> and the bastion cannot determine the client IP (e.g. missing `SSH_CLIENT`), the connection
> is **denied** (fail-closed policy). This prevents accidental bypass of IP-based access controls.

---

### 🛡️ **Yubico PIV / Hardware Key Attestation**

PIV attestation lets users prove that their SSH private key was generated inside a hardware token
(e.g. YubiKey) and cannot be exported. The full x509 attestation chain is verified against
admin-registered CA certificates before the key is accepted.

**Admin setup:**
```
pivAddTrustAnchor --name yubico-root --cert /path/to/yubico-piv-ca.pem
pivListTrustAnchors
pivRemoveTrustAnchor --name yubico-root
```

**User workflow (YubiKey):**
```bash
# Export attestation data from YubiKey
yubico-piv-tool --action=attest --slot=9a > attest.pem
yubico-piv-tool --action=read-cert --slot=f9 > intermediate.pem
ssh-keygen -D /usr/lib/x86_64-linux-gnu/libykcs11.so -e > my_piv_key.pub

# Add the key to the bastion (chain is verified server-side)
selfAddIngressKeyPIV --attest attest.pem --intermediate intermediate.pem $(cat my_piv_key.pub)
```

Keys added via PIV attestation are marked `PIV` in `selfListIngressKeys`.

---

### 🐚 **Mosh Support**

goBastion transparently passes through `mosh-server` invocations, enabling [Mosh](https://mosh.org/)
sessions through the bastion. No special configuration is needed on the client side.

```bash
# Standard mosh usage - works through the bastion
mosh --ssh="ssh -J user@bastion:2222" user@my-server
```

The bastion detects the `mosh-server` command in `SSH_ORIGINAL_COMMAND` and exec's it directly.
UDP ports 60001-61000 must be open on the **target server** (not the bastion) for the Mosh UDP connection.

---

### 📜 **TTY Session Recording**

| Command      | Description                                                                |
|--------------|-----------------------------------------------------------------------------|
| 📋 `ttyList` | List recorded SSH sessions. |
| ▶️ `ttyPlay` | Replay a recorded SSH session.                                              |

---

### 🔗 **Bastion-to-Bastion Chaining (Multi-Hop SSH)**

goBastion supports transparent multi-hop SSH through one or more intermediate bastions using the `--via` flag.

#### Syntax

```
user@final-target --via user@hop1[:port] [--via user@hop2[:port] ...]
```

- The **first argument** (without a flag) is always the **final target machine**.
- Each `--via` specifies an **intermediate bastion**, in order from outermost to innermost.
- Ports default to `22` if not specified.
- The `--via` flag is intentionally distinct from all SSH flags (no conflict).

#### How it works

goBastion translates the chain to SSH native ProxyJump:

```
phd@192.1.1.2 --via phd@10.0.0.1 --via phd@1.3.2.1
  → ssh -J phd@10.0.0.1:22,phd@1.3.2.1:22 phd@192.1.1.2
```

**Connection topology (two hops):**

```mermaid
flowchart LR
    U(["👤 User\nworkstation"])
    B(["🏰 goBastion\n:2222"])
    H1(["🔀 Hop 1\n10.0.0.1:22"])
    H2(["🔀 Hop 2\n1.3.2.1:22"])
    T(["🖥️ Target\n192.1.1.2:22"])

    U -- "ssh -tp 2222 user@bastion --\nphd@192.1.1.2\n--via phd@10.0.0.1\n--via phd@1.3.2.1" --> B
    B -- "SSH ProxyJump -J" --> H1
    H1 -. "tunnelled" .-> H2
    H2 -. "tunnelled" .-> T

    style U fill:#4a90d9,color:#fff,stroke:#2c5f8a
    style B fill:#e8a838,color:#fff,stroke:#b07820
    style H1 fill:#6abf6a,color:#fff,stroke:#3d8f3d
    style H2 fill:#6abf6a,color:#fff,stroke:#3d8f3d
    style T fill:#9b59b6,color:#fff,stroke:#6c3483
```

**Sequence — what happens step by step:**

```mermaid
sequenceDiagram
    actor U as 👤 User
    participant B as 🏰 goBastion :2222
    participant H1 as 🔀 Hop 1 (10.0.0.1)
    participant H2 as 🔀 Hop 2 (1.3.2.1)
    participant T as 🖥️ Target (192.1.1.2)

    U->>B: ssh -tp 2222 user@bastion -- phd@192.1.1.2 --via phd@10.0.0.1 --via phd@1.3.2.1
    Note over B: Parses --via flags<br/>Checks access entry for 192.1.1.2<br/>Builds: ssh -J 10.0.0.1:22,1.3.2.1:22 phd@192.1.1.2
    B->>H1: TCP connect (ProxyJump — bastion egress key)
    H1->>H2: TCP tunnel (ProxyJump hop 2)
    H2->>T: SSH connect with bastion egress key
    T-->>U: ✅ Interactive session (fully audited)
    Note over B: Audit log records: user, hops chain,<br/>target, session ID, timestamp
```

#### Prerequisites

1. The bastion must have a valid **access entry** for the final target (`selfAddAccess` or `groupAddAccess`).
2. The bastion's **egress key** must be authorized on each intermediate hop.
3. Each intermediate hop must have the bastion's egress public key in its `authorized_keys`.

#### Examples

**Single intermediate bastion:**
```sh
ssh -tp 2222 user@bastion -- phd@192.168.1.50 --via phd@10.0.0.1
```

**Two intermediate bastions with custom ports:**
```sh
ssh -tp 2222 user@bastion -- phd@192.1.1.2 --via phd@10.0.0.1:2222 --via phd@1.3.2.1
```

**With alias shorthand:**
```sh
alias gobastion='ssh -tp 2222 user@bastion --'
gobastion phd@192.1.1.2 --via phd@10.0.0.1 --via phd@1.3.2.1
```

**Combined with non-interactive command:**
```sh
# Run a command on the final target via two hops
ssh -tp 2222 user@bastion -- phd@192.1.1.2 --via phd@10.0.0.1 ls -la /etc
```

> **Audit**: the full hop chain (`jump_chain`) is recorded in the structured audit log for every multi-hop connection.

---

### 🌐 **Trusted Realms**

Realms are **named, registered intermediate bastions** — a convenient alternative to typing raw IPs in `--via` chains. They also store the trusted public key and allowed source CIDRs for auditing purposes.

> Realms require the `realmCreate` permission (admin, superowner, or restricted grant).

#### Commands

| Command                | Description |
|------------------------|-------------|
| `realmCreate`          | Register a new trusted bastion endpoint. |
| `realmList`            | List all configured realms. |
| `realmInfo`            | Show full details for one realm. |
| `realmDelete`          | Remove a realm entry. |

#### Full Usage

**Register a realm:**
```sh
# Interactive
ssh -tp 2222 user@bastion -- -osh realmCreate \
  --realm eu-bastion \
  --bastion 10.0.0.1 \
  --port 2222 \
  --from 10.0.0.0/8,192.168.0.0/16 \
  --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3..."

# JSON output
ssh -tp 2222 user@bastion -- -osh realmList --json-pretty
```

**List realms:**
```sh
ssh -tp 2222 user@bastion -- -osh realmList
```

**Inspect one realm:**
```sh
ssh -tp 2222 user@bastion -- -osh realmInfo --realm eu-bastion
```

**Delete a realm:**
```sh
ssh -tp 2222 user@bastion -- -osh realmDelete --realm eu-bastion
```

#### Using a Realm in a hop chain

Once registered, you can use the realm's `BastionHost` directly with `--via`:
```sh
# The realm "eu-bastion" has BastionHost=10.0.0.1, BastionPort=2222
gobastion deploy@target-server --via deploy@10.0.0.1:2222
```

---

### 👤 **Special Account Roles**

Beyond the standard `user` / `admin` roles, goBastion supports two optional account modifiers settable at creation or modification time.

#### OSH-Only accounts (`--osh-only`)

An OSH-only account can **only run `-osh` commands** — it cannot open interactive SSH sessions or connect to target servers. Ideal for automation accounts, CI pipelines, and API callers.

```sh
# Create an automation account
ssh -tp 2222 admin@bastion -- -osh accountCreate --account ci-bot --osh-only

# Modify an existing account
ssh -tp 2222 admin@bastion -- -osh accountModify --account ci-bot --oshOnly true
```

Behavior:
- Interactive login → denied immediately.
- SSH commands to target servers → denied.
- `-osh selfListAccesses`, `-osh groupList`, etc. → allowed.

#### SuperOwner accounts (`--superowner`)

A SuperOwner account has **implicit owner privileges on every group** without being explicitly added to them. Useful for on-call engineers or senior SREs who need broad visibility.

```sh
# Create a superowner account
ssh -tp 2222 admin@bastion -- -osh accountCreate --account sre-lead --superowner

# Grant superowner to an existing account
ssh -tp 2222 admin@bastion -- -osh accountModify --account sre-lead --superOwner true
```

Behavior:
- Can manage any group (add/remove members, accesses, aliases).
- Can execute all restricted commands (`realmCreate`, `pivAddTrustAnchor`, etc.).
- Does **not** grant admin-level account management (create/delete users) unless the account is also admin.

---

### 🔒 **Restricted Command Grants**

Restricted commands (such as `realmCreate`, `pivAddTrustAnchor`) normally require admin or superowner privileges. Admins can delegate individual restricted commands to specific non-admin users using grants.

> Only admins and superowners can manage grants.

#### Commands

| Command                  | Description |
|--------------------------|-------------|
| `restrictedGrantAdd`     | Grant a restricted command to a user. |
| `restrictedGrantDel`     | Remove a restricted command grant. |
| `restrictedGrantList`    | List all grants (optionally filtered by user). |

#### Examples

```sh
# Allow user "alice" to manage realms without making her an admin
ssh -tp 2222 admin@bastion -- -osh restrictedGrantAdd --user alice --command realmCreate
ssh -tp 2222 admin@bastion -- -osh restrictedGrantAdd --user alice --command realmDelete
ssh -tp 2222 admin@bastion -- -osh restrictedGrantAdd --user alice --command realmList
ssh -tp 2222 admin@bastion -- -osh restrictedGrantAdd --user alice --command realmInfo

# Allow user "bob" to manage PIV trust anchors
ssh -tp 2222 admin@bastion -- -osh restrictedGrantAdd --user bob --command pivAddTrustAnchor
ssh -tp 2222 admin@bastion -- -osh restrictedGrantAdd --user bob --command pivListTrustAnchors

# List all grants
ssh -tp 2222 admin@bastion -- -osh restrictedGrantList

# List grants for a specific user
ssh -tp 2222 admin@bastion -- -osh restrictedGrantList --user alice

# Revoke a grant
ssh -tp 2222 admin@bastion -- -osh restrictedGrantDel --user alice --command realmCreate
```

---

### 📜 **Misc Commands**

| Command   | Description                                    |
|-----------|------------------------------------------------|
| ❓ `help`  | Display the help menu with available commands. |
| ℹ️ `info` | Show application version and details.          |
| 🚪 `exit` | Exit the application.                          |

---

### 🧩 **JSON API over SSH (`-osh`)**

Non-interactive `-osh` commands support machine-readable output formats:

| Flag | Output format |
|------|---------------|
| `--json` | Compact JSON payload between `JSON_START` / `JSON_END` |
| `--json-pretty` | Pretty-printed JSON payload between `JSON_START` / `JSON_END` |
| `--json-greppable` | One-line payload prefixed by `JSON_OUTPUT=` |

Example:
```sh
ssh -p 2222 user@bastion -- -osh groupList --json-pretty
```

---

## 📊 **Permissions Matrix**

### 🔐 **Admin Permissions**

- `accountAddAccess`
- `accountCreate`
- `accountDelAccess`
- `accountDelete`
- `accountInfo`
- `accountList`
- `accountListAccess`
- `accountListIngressKeys`
- `accountListEgressKeys`
- `accountModify`
- `accountSetPassword`
- `whoHasAccessTo`
- `accountDisableTOTP`
- `pivAddTrustAnchor`
- `pivListTrustAnchors`
- `pivRemoveTrustAnchor`
- `groupCreate`
- `groupDelete`
- `realmCreate`
- `realmList`
- `realmInfo`
- `realmDelete`
- `restrictedGrantAdd`
- `restrictedGrantDel`
- `restrictedGrantList`

> **Notes**:
> - `ttyList` and `ttyPlay` are available to all users (for their own sessions) and to admins (for all sessions).
> - Realm and PIV commands can be delegated to non-admin users via `restrictedGrantAdd`.
> - **SuperOwner** accounts have admin-equivalent access to all of the above realm/restricted commands.

### 🛡️ **Restricted Commands (delegatable)**

The following commands require admin or superowner by default, but can be granted to individual users via `restrictedGrantAdd`:

| Command                | Default             | Grantable to regular users |
|------------------------|---------------------|:--------------------------:|
| `realmCreate`          | Admin / SuperOwner  | ✅                         |
| `realmList`            | Admin / SuperOwner  | ✅                         |
| `realmInfo`            | Admin / SuperOwner  | ✅                         |
| `realmDelete`          | Admin / SuperOwner  | ✅                         |
| `pivAddTrustAnchor`    | Admin / SuperOwner  | ✅                         |
| `pivListTrustAnchors`  | Admin / SuperOwner  | ✅                         |
| `pivRemoveTrustAnchor` | Admin / SuperOwner  | ✅                         |

### 👥 **Group Permissions**

| Permission               | Owner | ACLKeeper | GateKeeper | Member |
| ------------------------ | :---: | :-------: | :--------: | :----: |
| `groupAddAccess`         | ✅    | ✅        | ✅         |        |
| `groupDelAccess`         | ✅    | ✅        | ✅         |        |
| `groupSetMFA`            | ✅    |           |            |        |
| `groupAddMember`         | ✅    | ✅        |            |        |
| `groupDelMember`         | ✅    | ✅        |            |        |
| `groupGenerateEgressKey` | ✅    |           |            |        |
| `groupAddAlias`          | ✅    | ✅        | ✅         |        |
| `groupDelAlias`          | ✅    | ✅        | ✅         |        |
| `groupInfo`              | ✅    | ✅        | ✅         | ✅     |
| `groupList`              | ✅    | ✅        | ✅         | ✅     |
| `groupListAccesses`      | ✅    | ✅        | ✅         | ✅     |
| `groupListAliases`       | ✅    | ✅        | ✅         | ✅     |
| `groupListEgressKeys`    | ✅    | ✅        | ✅         | ✅     |

### 👤 **Self Permissions**

- `selfAddAccess`
- `selfAddAlias`
- `selfAddIngressKey`
- `selfAddIngressKeyPIV`
- `selfChangePassword`
- `selfDelAccess`
- `selfDelAlias`
- `selfDelIngressKey`
- `selfDisablePassword`
- `selfDisableTOTP`
- `selfGenerateBackupCodes`
- `selfGenerateEgressKey`
- `selfListAccesses`
- `selfListAliases`
- `selfListEgressKeys`
- `selfListIngressKeys`
- `selfRemoveHostFromKnownHosts`
- `selfReplaceKnownHost`
- `selfSetPassword`
- `selfSetupTOTP`
- `selfShowBackupCodeCount`
- `ttyList` *(own sessions only)*
- `ttyPlay` *(own sessions only)*

⚠ **Alias Priority Warning**:
If an alias is defined by the user (`selfAddAlias`) and the group defines an alias with the same name (`groupAddAlias`), **the user-defined alias always takes precedence**

### 📜 **Misc Permissions**

- `help`
- `info`
- `exit`

---

## 📥 **Installation**

1. Clone the repository:

   ```sh
   git clone https://github.com/phd59fr/goBastion.git
   cd goBastion
   ```

2. Build the Docker container:

   ```sh
   docker build -t gobastion .
   ```

3. Run the Docker container:

   ```sh
   docker run --name gobastion --hostname goBastion -it -p 2222:22 gobastion:latest
   ```

   You can also use the official **Docker Hub** image:

   ```sh
   docker run --name gobastion --hostname goBastion -it -p 2222:22 phd59fr/gobastion:latest
   ```

   (optional) 3a. Launch the container with a volume to persist the database and ttyrec:

   ```sh
   docker run --name gobastion --hostname goBastion -it -p 2222:22 \
     -v /path/to/your/dbvolume:/var/lib/goBastion \
     -v /path/to/your/ttyvolume:/app/ttyrec gobastion:latest
   ```

   (optional) 3b. Use an external database (see [Environment Variables](#-environment-variables)):

   ```sh
   docker run --name gobastion --hostname goBastion -it -p 2222:22 \
     -e DB_DRIVER=postgres \
     -e DB_DSN="host=db user=gobastion password=secret dbname=gobastion port=5432 sslmode=disable" \
     gobastion:latest
   ```

4. Simplified usage with an Alias (Optional):

   ```sh
   alias gobastion='ssh -tp 2222 user@localhost --'
   ```

5. Connect to the bastion host (interactive mode):

   ```sh
   ssh -tp 2222 user@localhost (or alias gobastion)
   ```

   (optional) 5a. Connect to the bastion host with a command (non-interactive mode):

   ```sh
   ssh -tp 2222 user@localhost -- -osh selfListIngressKeys (or alias gobastion -osh selfListIngressKeys)
   ```

   (optional) 5b. Connect to the target host through the bastion:

   ```sh
   ssh -tp 2222 user@localhost -- user@targethost (ssh options supported) (or alias gobastion user@targethost)
   ```

   (optional) 5b-bis. Connect through multiple bastions (bastion-to-bastion chaining):

   ```sh
   # Two intermediate hops: 10.0.0.1 → 1.3.2.1 → 192.1.1.2
   ssh -tp 2222 user@bastion -- phd@192.1.1.2 --via phd@10.0.0.1 --via phd@1.3.2.1
   ```

   → See the **[Bastion-to-Bastion Chaining](#-bastion-to-bastion-chaining-multi-hop-ssh)** section for full documentation, realm integration, and advanced examples.

   (optional) 5c. Use SFTP / SCP / rsync through the bastion — see [SCP / SFTP / rsync Passthrough](#-scp--sftp--rsync-passthrough) for full configuration details.

---

## ⚙️ **Environment Variables**

| Variable        | Default | Description |
|-----------------|---------|-------------|
| `DB_DRIVER`     | `sqlite` | Database backend: `sqlite`, `mysql`, or `postgres` |
| `DB_DSN`        | *(auto)* | Database connection string. For SQLite, defaults to `/var/lib/goBastion/bastion.db`. Required for `mysql` and `postgres`. |
| `EGRESS_ENC_KEY`| *(none)* | AES key for encrypting egress private keys at rest. See [Egress Key Encryption](#-egress-key-encryption). |
| `LOG_FORMAT`    | `json`   | Log output format: `json` (structured JSON, compatible with log aggregators) or `plain` (human-readable text for local debugging). |

### DSN examples

**MySQL:**
```
DB_DRIVER=mysql
DB_DSN=gobastion:secret@tcp(db:3306)/gobastion?charset=utf8mb4&parseTime=True&loc=Local
```

**PostgreSQL:**
```
DB_DRIVER=postgres
DB_DSN=host=db user=gobastion password=secret dbname=gobastion port=5432 sslmode=disable
```

**SQLite (custom path):**
```
DB_DRIVER=sqlite
DB_DSN=file:/data/mybastion.db?cache=shared&mode=rwc
```

### Manual Schema Setup

If the goBastion app user does not have `CREATE TABLE` / `ALTER` permissions on your database, the DBA can pre-create the schema manually.

The `sql/` directory contains ready-to-run schema files:

| File | Database |
|------|----------|
| `sql/postgres.sql` | PostgreSQL |
| `sql/mysql.sql` | MySQL |

**PostgreSQL:**
```sh
psql -h <host> -U <admin> -d <dbname> -f sql/postgres.sql
```

**MySQL:**
```sh
mysql -h <host> -u <admin> -p <dbname> < sql/mysql.sql
```

After creating the schema, grant the goBastion app user minimal privileges:

**PostgreSQL:**
```sql
GRANT USAGE ON SCHEMA public TO gobastion;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gobastion;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gobastion;
```

**MySQL:**
```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON gobastion.* TO 'gobastion'@'%';
FLUSH PRIVILEGES;
```

> The app user only needs `SELECT`, `INSERT`, `UPDATE`, `DELETE` — no `CREATE`, `ALTER`, or `DROP`.

### 🔐 Egress Key Encryption

By default, egress private keys are stored in the database in **plaintext**. To encrypt them at rest, set the `EGRESS_ENC_KEY` environment variable:

```bash
# Generate a 32-byte AES-256 key
openssl rand -base64 32 > egress_key.txt
export EGRESS_ENC_KEY=$(cat egress_key.txt)
```

`EGRESS_ENC_KEY` accepts:
- Base64-encoded AES key (16/24/32 bytes)
- 32-byte raw passphrase

**Migration behavior:**
- If `EGRESS_ENC_KEY` is set **after** keys were already stored in plaintext, existing keys are automatically re-encrypted on next use (transparent migration).
- If `EGRESS_ENC_KEY` is **not set**, keys remain in plaintext (backward-compatible).

```sh
docker run --name gobastion --hostname goBastion -it -p 2222:22 \
  -e EGRESS_ENC_KEY="$(openssl rand -base64 32)" \
  gobastion:latest
```

---

## 🛠️ **Admin CLI Flags**

These flags are only available when running as `root` outside an SSH session:

| Flag | Command | Description                                                                                              |
|------|---------|----------------------------------------------------------------------------------------------------------|
| `--firstInstall` | `docker exec -it goBastion /app/goBastion --firstInstall` | Manually bootstrap the first admin user (interactive)                                                    |
| `--regenerateSSHHostKeys` | `docker exec -it goBastion /app/goBastion --regenerateSSHHostKeys` | Force-regenerate the bastion's SSH host keys                                                             |
| `--sync` | `docker exec goBastion /app/goBastion --sync` | Enforce DB state onto the OS immediately (DB is source of truth); also runs automatically every 5 minutes |
| `--dbExport` | `docker exec -i -e DB_EXPORT_KEY="$DB_EXPORT_KEY" goBastion /app/goBastion --dbExport > dump` | Dump the database as encrypted file to stdout                                                            |
| `--dbImport` | `docker exec -i -e DB_EXPORT_KEY="$DB_EXPORT_KEY" goBastion /app/goBastion --dbImport < dump` | Restore the database from encrypted file on stdin                                                        |
| `--disableTOTP` | `docker exec -it goBastion /app/goBastion --disableTOTP <user>` | Disable TOTP, password MFA, and backup codes for a user (recovery)                                       |

### 🔐 Database Export / Import

The export is now a **single encrypted file**, independent of SQL dialects.

It is designed for portability across:

- SQLite
- MySQL
- PostgreSQL

Encryption is mandatory.

---

### 🔑 Generating and using the encryption key

```bash
openssl rand -base64 32 > export_key.txt
export DB_EXPORT_KEY=$(cat export_key.txt)
````

`DB_EXPORT_KEY` can be:

* base64 AES key (16/24/32 bytes)
* raw AES key
* passphrase (derived using Argon2id)

---

### 📤 Encrypted export

```bash
docker exec -i -e DB_EXPORT_KEY="$DB_EXPORT_KEY" goBastion /app/goBastion --dbExport > dump
```

---

### 📥 Encrypted import

```bash
docker exec -i -e DB_EXPORT_KEY="$DB_EXPORT_KEY" goBastion /app/goBastion --dbImport < dump
```

---

### ⚠️ Notes

* Target DB must already have schema (AutoMigrate)
* Target DB must be empty
* Same key must be used for export/import
* Output goes to stdout, logs to stderr

---

## 🤝 **Contributing**

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.
Here’s how you can help:

* Report bugs
* Suggest features
* Submit pull requests

To contribute:

1. Fork the project
2. Create a new branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a pull request

---

## 📄 **License**

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

## ❤️ Support

A simple star on this project repo is enough to keep me motivated for days. If you’re excited about this project, let me know with a tweet.
If you have any questions, feel free to reach out to me on [X](https://x.com/xxPHDxx).

---
