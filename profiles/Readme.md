These profiles support the per-session database client sandbox. Both derive from the Moby profiles (Apache 2.0, license in LICENSE.moby):

- db-isolation-seccomp.json: https://github.com/moby/profiles/blob/main/seccomp/default.json. Adds namespace setup operations conditional on SYS_ADMIN; all other Docker defaults are retained.
- gobastion-db.apparmor: https://github.com/moby/profiles/blob/main/apparmor/template.go. Replaces the blanket mount denial with rules for NsJail setup paths and allows pivot_root. Keeps the default /proc and /sys write restrictions and rejects AF_VSOCK and AF_ALG sockets.

Load AppArmor on the Docker host with `sudo apparmor_parser -r profiles/gobastion-db.apparmor`, then use `--security-opt apparmor=gobastion-db`. Do not disable AppArmor or seccomp to work around a denied setup operation. The staging mount rule includes the directory itself (`/{,**}`), which is required for the temporary root mount. Procfs is not mounted inside the jail. The native client receives a second seccomp filter inside NsJail and has no capabilities; it cannot perform the supervisor's setup operations.
