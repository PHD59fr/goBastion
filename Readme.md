# 🚀 **goBastion**

**goBastion** is a tool for managing SSH access, user roles, and keys on a bastion host. The project is currently under active development, and contributions are welcome!

🔗 **GitHub Repository**: [https://github.com/phd59fr/goBastion](https://github.com/phd59fr/goBastion)

🐳 **Docker Hub Image**: [https://hub.docker.com/r/phd59fr/gobastion](https://hub.docker.com/r/phd59fr/gobastion)

---

## ✨ **Key Concept – Database as the Source of Truth**

In **goBastion**, **the database is the single source of truth** for SSH keys and access management. This means that the system always reflects the state of the database. Any key or access added manually to the system without passing through the bastion will be **automatically removed** to maintain consistency.

### How it works:

* **Key Addition**:
  When a user adds an SSH key, it is first validated and stored in the database. The bastion then automatically synchronizes the database with the system, adding the key to the appropriate location.

* **Automatic Synchronization** (Not Implemented):
  The bastion periodically checks the system for any discrepancies. If it finds an SSH key not in the database, the key is immediately removed from the system to ensure security and consistency.

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
| ➕ `selfAddIngressKey`            | Add a new ingress SSH key.                                                   |
| ❌ `selfDelIngressKey`            | Delete an ingress SSH key.                                                   |
| 🔑 `selfListEgressKeys`          | List your egress SSH keys (keys for connecting from the bastion to servers). |
| 🔑 `selfGenerateEgressKey`       | Generate a new egress SSH key.                                               |
| 📋 `selfListAccesses`            | List your personal server accesses.                                          |
| ➕ `selfAddAccess`                | Add access to a personal server.                                             |
| ❌ `selfDelAccess`                | Remove access to a personal server.                                          |
| 📋 `selfListAliases`             | List your personal SSH aliases.                                              |
| ➕ `selfAddAlias`                 | Add a personal SSH alias.                                                    |
| ❌ `selfDelAlias`                 | Delete a personal SSH alias.                                                 |
| ❌ `selfRemoveHostFromKnownHosts` | Remove a host from your known\_hosts file.                                   |

---

### 🦸 **Admin Commands (Manage Other Accounts)**

| Command                     | Description                                           |
|-----------------------------|-------------------------------------------------------|
| 📋 `accountList`            | List all user accounts.                               |
| ℹ️ `accountInfo`            | Show detailed information about a user account.       |
| ➕ `accountCreate`           | Create a new user account.                            |
| ❌ `accountDelete`           | Delete a user account.                                |
| ✏️ `accountModify`          | Modify a user account (promote/demote to admin/user). |
| 🔑 `accountListIngressKeys` | List the ingress SSH keys of a user.                  |
| 🔑 `accountListEgressKeys`  | List the egress SSH keys of a user.                   |
| 📋 `accountListAccess`      | List all server accesses of a user.                   |
| ➕ `accountAddAccess`        | Grant a user access to a server.                      |
| ❌ `accountDelAccess`        | Remove a user's access to a server.                   |
| 📋 `whoHasAccessTo`         | Show all users with access to a specific server.      |

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
| 📋 `groupListAccess`        | List all accesses assigned to a group.            |
| ➕ `groupAddAccess`          | Grant access to a group.                          |
| ❌ `groupDelAccess`          | Remove access from a group.                       |
| ➕ `groupAddAlias`           | Add a group SSH alias.                            |
| ❌ `groupDelAlias`           | Delete a group SSH alias.                         |
| 📋 `groupListAliases`       | List all group SSH aliases.                       |

---

### 📜 **TTY Session Recording**

| Command      | Description                                    |
|--------------|------------------------------------------------|
| 📋 `ttyList` | List available recorded SSH sessions (ttyrec). |
| ▶️ `ttyPlay` | Replay a recorded SSH session.                 |

---

### 📜 **Misc Commands**

| Command   | Description                                    |
|-----------|------------------------------------------------|
| ❓ `help`  | Display the help menu with available commands. |
| ℹ️ `info` | Show application version and details.          |
| 🚪 `exit` | Exit the application.                          |

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
- `whoHasAccessTo`
- `groupCreate`
- `groupDelete`
- `ttyList`
- `ttyPlay`

### 👥 **Group Permissions**

| Permission               | Owner | ACLKeeper | GateKeeper | Member |
| ------------------------ | :---: | :-------: | :--------: | :----: |
| `groupAddAccess`         | ✅    | ✅        | ✅         |        |
| `groupDelAccess`         | ✅    | ✅        | ✅         |        |
| `groupAddMember`         | ✅    | ✅        |           |        |
| `groupDelMember`         | ✅    | ✅        |           |        |
| `groupGenerateEgressKey` | ✅    |          |           |        |
| `groupInfo`              | ✅    | ✅        | ✅         | ✅     |
| `groupList`              | ✅    | ✅        | ✅         | ✅     |
| `groupListAccesses`      | ✅    | ✅        | ✅         | ✅     |
| `groupListEgressKeys`    | ✅    | ✅        | ✅         | ✅     |

### 👤 **Self Permissions**

- `selfAddAccess`
- `selfAddAlias`
- `selfAddIngressKey`
- `selfDelAccess`
- `selfDelAlias`
- `selfDelIngressKey`
- `selfGenerateEgressKey`
- `selfListAccesses`
- `selfListAliases`
- `selfListEgressKeys`
- `selfListIngressKeys`
- `selfRemoveHostFromKnownHosts`

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
   docker run --name gobastion --hostname goBastion -d -p 2222:22 gobastion:latest
   ```

   You can also use the official **Docker Hub** image:

   ```sh
   docker run --name gobastion --hostname goBastion -d -p 2222:22 phd59fr/gobastion:latest
   ```

   (optional) 3a. Launch the container with a volume to persist the database and ttyrec:

   ```sh
   docker run --name gobastion --hostname goBastion -d -p 2222:22 \
     -v /path/to/your/dbvolume:/var/lib/goBastion \
     -v /path/to/your/ttyvolume:/app/ttyrec gobastion:latest
   ```

4. Create the first user:

   ```sh
   docker exec -it gobastion /app/goBastion --firstInstall
   ```

5. Simplified usage with an Alias (Optional):

   ```sh
   alias gobastion='ssh -tp 2222 user@localhost --'
   ```

6. Connect to the bastion host (interactive mode):

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
