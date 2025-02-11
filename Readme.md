# 🚀 **goBastion**

**goBastion** is a tool for managing SSH access, user roles, and keys on a bastion host. The project is currently under active development, and contributions are welcome!

---

## ⚠️ **Work in Progress**

This project is a work in progress and may change frequently. Some features may not be fully implemented or stable yet.
Big task to do: refactor the code, clean up error handling, and ensure proper return values.
---

## ✨ **Key Concept – Database as the Source of Truth**

In **goBastion**, **the database is the single source of truth** for SSH keys and access management. This means that the system always reflects the state of the database. Any key or access added manually to the system without passing through the bastion will be **automatically removed** to maintain consistency.

### How it works:
- **Key Addition**:  
  When a user adds an SSH key, it is first validated and stored in the database. The bastion then automatically synchronizes the database with the system, adding the key to the appropriate location.

- **Automatic Synchronization**:  
  The bastion periodically checks the system for any discrepancies. If it finds an SSH key that is not in the database, the key is immediately removed from the system to ensure security and consistency.

### **Advantages of this Approach**
- **Centralized Control**: All modifications go through the bastion, ensuring tight access management.
- **Enhanced Security**: Unauthorized keys cannot remain on the system.
- **State Consistency**: The system always mirrors the database state.
- **Audit and Traceability**: Every change is recorded in the database.
- **Fully Automated Management**: No need for manual checks; synchronization handles everything.
- **Easy Exportability**: The system can be deployed on a new container effortlessly. Since the database is the source of truth, replicating it with synchronization scripts provides a functional bastion on a new instance.

---

## 🔍 **Features Overview**

### 🔐 **Self Commands**
| Command                     | Status     |
|-----------------------------|------------|
| 🗝️ `selfListIngressKeys`   | ✅ **Work** |
| ➕ `selfAddIngressKey`       | ✅ **Work** |
| ❌ `selfDelIngressKey`       | ✅ **Work** |
| 🗝️ `selfListEgressKeys`    | ✅ **Work** |
| 🗝️ `selfGenerateEgressKey` | ✅ **Work** |
| 📋 `selfListAccesses`       | ✅ **Work** |
| ➕ `selfAddPersonalAccess`   | ✅ **Work** |
| ❌ `selfDelPersonalAccess`   | ✅ **Work** |

---

### 🛠️ **Admin Commands**

#### **Account Management**
| Command                      | Status     |
|------------------------------|------------|
| 📋 `accountList`             | ✅ **Work** |
| ℹ️ `accountInfo`             | ✅ **Work** |
| ➕ `accountCreate`            | ✅ **Work** |
| ❌ `accountDelete`            | ✅ **Work** |
| ✏️ `accountModify`           | ✅ **Work** |
| 🗝️ `accountListIngressKeys` | ✅ **Work** |
| 🗝️ `accountListEgressKeys`  | ✅ **Work** |
| 📋 `accountListAccesses`     | ✅ **Work** |
| ➕ `accountAddPersonalAccess` | ✅ **Work** |
| ❌ `accountDelPersonalAccess` | ✅ **Work** |
| 📋 `whoHasAccessTo`          | ✅ **Work** |



---

#### **Group Management**
| Command                      | Status     |
|------------------------------|------------|
| ℹ️ `groupInfo`               | ✅ **Work** |
| 📋 `groupList`               | ✅ **Work** |
| ➕ `groupCreate`              | ✅ **Work** |
| ❌ `groupDelete`              | ✅ **Work** |
| ➕ `groupAddMember`           | ✅ **Work** |
| ❌ `groupDelMember`           | ✅ **Work** |
| 🗝️ `groupGenerateEgressKey` | ✅ **Work** |
| 🗝️ `groupListEgressKeys`    | ✅ **Work** |
| ➕ `groupAddAccess`           | ✅ **Work** |
| ❌ `groupDelAccess`           | ✅ **Work** |
| 📋 `groupListAccess`         | ✅ **Work** |

---

### 📜 **Misc Commands**
| Command   | Status     |
|-----------|------------|
| ❓ `help`  | ✅ **Work** |
| ℹ️ `info` | ✅ **Work** |
| 🚪 `exit` | ✅ **Work** |

---


## 🛠️ **Installation**

1. Clone the repository or use the docker image phd59fr/gobastion:latest(step 3):
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
   You can use the docker hub image:
   ```sh
    docker run --name gobastion --hostname goBastion -d -p 2222:22 phd59fr/gobastion:latest
    ```
   (optional) 3a. Launch the container with a volume to persist the database and ttyrec:
   ```sh
    docker run --name gobastion --hostname goBastion -d -p 2222:22 -v /path/to/your/volume:/var/lib/goBastion -v /path/to/your/volume:/app/ttyrec  gobastion:latest
   ```
4. Create the first user:
   ```sh
   docker exec -it gobastion /app/goBastion --firstInstall
   ```
   (optional) 4a. Restore your bastion from a database (require 3a):
   ```sh
   docker exec -it gobastion /app/goBastion --restore
   ```
5. Connect to the bastion host (interactive mode):
   ```sh
   ssh -tp 2222 user@localhost
   ```
   (optional) 5a. Connect to the bastion host with command (non-interactive mode):
   ```sh
   ssh -tp 2222 user@localhost -- -osh selfListIngressKeys
   ```
   (optional) 5b. Connect to the target host through the bastion:
   ```sh
   ssh -tp 2222 user@localhost -- user@targethost (ssh options supported)
   ```
---

## 🤝 **Contributing**

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.
Here’s how you can help:

- Report bugs
- Suggest features
- Submit pull requests

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
If you have any questions, feel free to reach out to me on [Twitter](https://twitter.com/xxPHDxx).

---