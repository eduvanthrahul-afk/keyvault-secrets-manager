# 🔐 KeyVault (Kypher) - Enterprise Zero-Knowledge Secrets & API Key Manager

<p align="center">
  <img src="https://img.shields.io/badge/Spring_Boot-3.2.2-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" alt="Spring Boot" />
  <img src="https://img.shields.io/badge/Java_17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" alt="Java 17" />
  <img src="https://img.shields.io/badge/MySQL_8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white" alt="MySQL" />
  <img src="https://img.shields.io/badge/Web_Crypto_API-AES--256--GCM-E34F26?style=for-the-badge&logo=html5&logoColor=white" alt="Web Crypto" />
  <img src="https://img.shields.io/badge/Node.js_CLI-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js CLI" />
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License MIT" />
</p>

<p align="center">
  <b>A production-grade, enterprise Zero-Knowledge Secrets Management Platform and Developer CLI.</b><br>
  Securely store, organize, rotate, version, and inject environment variables & API credentials across distributed engineering teams.
</p>

---

> 🛡️ **Zero-Knowledge Security Guarantee:** Plaintext secrets and master passwords never touch the server or network unencrypted. All cryptographic derivation (`PBKDF2` 100k rounds) and encryption/decryption (`AES-256-GCM`) occur exclusively in client memory (Browser Web Crypto API or CLI runtime). The server and database only handle salted hashes, random Initialization Vectors (IV), and ciphertext.

---

### ⚡ Quick Demo Credentials

For testing and demonstration, use the pre-seeded account:

| Key | Value |
| :--- | :--- |
| **Frontend URL** | [`http://localhost:3000/login.html`](http://localhost:3000/login.html) |
| **Demo Email** | `demo@keyvault.com` |
| **Master Password** | `Password@123` |

---

## 📑 Table of Contents
1. [Core Features](#-core-features)
2. [Technical Architecture & Data Flow](#-technical-architecture--data-flow)
3. [Deep-Dive Cryptographic Protocol](#-deep-dive-cryptographic-protocol)
4. [Technology Stack](#-technology-stack)
5. [Repository Structure](#-repository-structure)
6. [Database Schema & ER Model](#-database-schema--er-model)
7. [Developer CLI (`kv-cli`) & Process Injection](#-developer-cli-kv-cli--process-injection)
8. [REST API Endpoints Reference](#-rest-api-endpoints-reference)
9. [Security & Anti-Abuse Hardening](#-security--anti-abuse-hardening)
10. [Local Setup & Running the Services](#-local-setup--running-the-services)
11. [Interview Cheatsheet & Architectural Highlights](#-interview-cheatsheet--architectural-highlights)

---

## 🚀 Core Features

### 1. 🔒 Zero-Knowledge Secret Management
- **Client-Side AES-256-GCM:** Keys are encrypted client-side with a unique 96-bit Initialization Vector (IV) for every write/update operation.
- **Environment Partitioning:** Separate secrets across `DEV`, `STAGING`, and `PROD` environments per project workspace.
- **Secret Masking & Clipboard Guard:** Masked UI by default with client-side reveal on demand and one-click clipboard copying.
- **Live Search & Tag Filters:** Instant client-side search across services, tags, and environments.

### 2. ⏳ Cryptographic Key Versioning & Rollback
- **Immutable Version History:** Every secret update creates an immutable version snapshot (`ApiKeyVersion`).
- **Version Diffs:** Inspect previous encrypted values and timestamps.
- **One-Click Instant Rollback:** Revert any API key to a prior historical version without exposing plaintext on the server.

### 3. 👥 Team Collaboration & Granular RBAC
- **Multi-Tenant Workspaces:** Organize secrets into dedicated projects.
- **Role-Based Access Control (RBAC):**
  - **`OWNER`:** Full workspace management, member invitations, role alterations, project deletion.
  - **`ADMIN`:** Key creation/updates, secret management, member invites.
  - **`MEMBER`:** Read/write permissions for secrets.
  - **`VIEWER`:** Read-only access to decrypted values.
- **Asymmetric Key Exchange:** Public-key cryptography (`RSA-OAEP` / `ECDH`) allows team members to decrypt shared project secrets without sharing master passwords.

### 4. 🤖 Machine Tokens & CI/CD Pipelines
- **Programmatic Secret Injection:** Generate scoped Machine Tokens (`mct_...`) for automated build pipelines, GitHub Actions, Docker containers, and Kubernetes pods.
- **Fine-Grained Permissions & Expiration:** Restrict machine tokens by project, environment, and lifespan.

### 5. 💻 Developer CLI (`kv-cli`)
- **Native CLI Runner:** Built with Node.js and Commander.js.
- **In-Memory Process Injection:** Command `kv-cli run --env prod -- npm start` decrypts secrets strictly in memory and spawns the target child process with injected environment variables — without writing `.env` files to disk.

### 6. 📜 Forensic Audit Logging & Compliance Trails
- **Comprehensive Activity Log:** Real-time recording of all sensitive actions (`KEY_CREATE`, `KEY_DECRYPT`, `KEY_UPDATE`, `KEY_DELETE`, `VERSION_ROLLBACK`, `MEMBER_INVITE`, `LOGIN`).
- **Contextual Metadata:** Tracks actor email, actor IP address, action timestamp, and affected resource ID.

### 7. ⏰ Automated Expiry Monitoring & Email Alerts
- **Background Cron Scheduler:** Daily cron scans for keys approaching expiration (7-day window).
- **Email Notifications:** Dispatch automated alerts via **Resend API** and **Spring Mail (SMTP)** to prevent unexpected service outages.

---

## 🏗 Technical Architecture & Data Flow

```
+-----------------------------------------------------------------------------------------+
|                                    CLIENT TIER                                          |
|                                                                                         |
|   +---------------------------------------+    +------------------------------------+   |
|   |         Web Browser Frontend          |    |          Developer CLI             |   |
|   |   (Vanilla JS + Web Crypto API)       |    |       (Node.js + kv-cli)           |   |
|   |                                       |    |                                    |   |
|   |  - PBKDF2 Key Derivation (100k iters) |    |  - Decrypts secrets in memory      |   |
|   |  - AES-256-GCM Encrypt / Decrypt      |    |  - Injects into child process env  |   |
|   |  - Session Key Memory Storage         |    |  - Zero plaintexts saved to disk   |   |
|   +-------------------+-------------------+    +-----------------+------------------+   |
+-----------------------|------------------------------------------|----------------------+
                        | HTTPS (JWT / Bearer Token)               |
                        v                                          v
+-----------------------------------------------------------------------------------------+
|                                  APPLICATION BACKEND                                    |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   |                             Spring Boot 3.2.2 REST API                          |   |
|   |                                                                                 |   |
|   |  +------------------------+  +------------------------+  +-------------------+  |   |
|   |  |     Security & Auth    |  |     Project & Keys     |  |   Team & Members  |  |   |
|   |  |  - JWT Filter / Cookie |  |  - High-Perf Summaries |  |   - RBAC Security |  |   |
|   |  |  - Bucket4j Rate Limit |  |  - Version Rollbacks   |  |   - Audit Service |  |   |
|   |  |  - Token Blacklisting  |  |  - Machine Tokens      |  |   - Email Alerts  |  |   |
|   |  +------------------------+  +------------------------+  +-------------------+  |   |
|   +----------------------------------------+----------------------------------------+   |
+--------------------------------------------|--------------------------------------------+
                                             | JPA / Hibernate
                                             v
+-----------------------------------------------------------------------------------------+
|                                     DATA TIER                                           |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   |                                MySQL 8.0 Database                               |   |
|   |                                                                                 |   |
|   |  - `users` (Salt, BCrypt Password Hash, Public Key, Encrypted Private Key)      |   |
|   |  - `projects` & `project_members` (UUID PK, RBAC Roles: OWNER, ADMIN, MEMBER)   |   |
|   |  - `api_keys` (Ciphertext, IV, Service, Env, Expiry) - NEVER PLAINTEXT!         |   |
|   |  - `api_key_versions` (Historical Ciphertext Snapshots & Rollback Data)         |   |
|   |  - `machine_tokens` & `audit_logs` (Immutable Compliance Activity Trail)        |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

---

## 🔐 Deep-Dive Cryptographic Protocol

The application implements a **2-Stage Key Derivation** protocol to ensure cryptographic separation of authentication and encryption keys:

```
                  +--------------------------+
                  | User's Master Password   |
                  +-------------+------------+
                                |
                                v
                +-------------------------------+
                | Salt (128-bit random from DB) |
                +---------------+---------------+
                                |
                                v  [PBKDF2: 100,000 iterations, SHA-256]
                +---------------+---------------+
                |           Auth_Hash           |
                +---------------+---------------+
                                |
        +-----------------------+-----------------------+
        |                                               |
        v (Sent to Backend)                             v (Kept in Browser Memory)
+-------------------------------+               +-------------------------------+
|       BCrypt Hashing          |               | PBKDF2 (100k iters, SHA-256)  |
|       (Stored in DB)          |               +---------------+---------------+
+-------------------------------+                               |
                                                                v
                                                +-------------------------------+
                                                |     Master Encryption Key     |
                                                |        (AES-256-GCM)          |
                                                +---------------+---------------+
                                                                |
                                                                v
                                                +-------------------------------+
                                                |  AES-GCM (Plaintext + 12B IV) |
                                                +---------------+---------------+
                                                                |
                                                                v
                                                +-------------------------------+
                                                |   Ciphertext + IV (To DB)     |
                                                +-------------------------------+
```

### Protocol Steps:
1. **Registration:**
   - Client generates a 128-bit cryptographically secure random `Salt`.
   - Client derives `Auth_Hash` using **PBKDF2 (100,000 iterations, SHA-256)**.
   - `Auth_Hash` is sent over TLS to the backend, which hashes it with **BCrypt** before storing in MySQL.
   - The master password is never transmitted.
2. **Key Derivation (Client-Side):**
   - Client runs a second PBKDF2 stage on `Auth_Hash` with the `Salt` to derive the 256-bit **Master Encryption Key**.
   - The Master Encryption Key is kept strictly in volatile memory.
3. **Encryption & Storage:**
   - Plaintext secret is encrypted with `AES-256-GCM` using a fresh 96-bit (12-byte) random Initialization Vector (`IV`).
   - The output `Ciphertext` and `IV` are sent to the backend.
4. **Decryption & Retrieval:**
   - Client fetches `Ciphertext` and `IV` from backend.
   - Client decrypts the payload in browser/CLI memory using the derived Master Encryption Key.

---

## 🛠 Technology Stack

### Backend
| Technology | Version | Purpose / Rationale |
| :--- | :--- | :--- |
| **Java** | 17 LTS | Modern LTS Java runtime with enhanced performance and records |
| **Spring Boot** | 3.2.2 | Production application framework with embedded Tomcat server |
| **Spring Security** | 6.x | Stateless JWT authentication, role authorization, and security filter chains |
| **Spring Data JPA** | 3.2.2 | ORM abstraction over Hibernate 6 with optimized single-query summaries |
| **MySQL Connector/J**| 8.3.0 | Relational database driver for high-throughput transactional queries |
| **JJWT** | 0.11.5 | JSON Web Token parsing, signing (HMAC-SHA256), and claims validation |
| **Bucket4j** | 8.10.1 | In-memory token bucket rate limiting for anti-brute force protection |
| **Caffeine Cache** | 3.x | High-performance near-cache for notification summaries and rate limit buckets |
| **Resend & JavaMail**| 1.x | Multi-provider transactional email delivery for OTPs and expiration alerts |
| **Lombok** | 1.18 | Boilerplate reduction for data models and DTO builders |

### Frontend
| Technology | Purpose / Rationale |
| :--- | :--- |
| **HTML5 & Vanilla CSS3** | High-performance UI without framework overhead; custom glassmorphism styling |
| **Vanilla JavaScript (ES6+)** | Lightweight modular scripts (`crypto.js`, `api.js`, `teams.js`, `audit.js`) |
| **Web Crypto API** | Browser-native hardware-accelerated cryptographic primitives (`SubtleCrypto`) |
| **FontAwesome 6.4** | Modern vector iconography for developer dashboard and security indicators |

### CLI Tool
| Technology | Purpose / Rationale |
| :--- | :--- |
| **Node.js (v24)** | Cross-platform JavaScript runtime for terminal CLI execution |
| **Commander.js** | Fluent CLI argument parsing, flags, and subcommand orchestration |
| **Axios** | HTTP client for interacting with the KeyVault REST API |
| **Chalk & Ora** | Terminal styling, colorized output, and dynamic spinners |

---

## 📂 Repository Structure

```
ApiManager/
├── backend/                             # Spring Boot 3 Backend
│   ├── src/main/java/com/apimanager/keyvault/
│   │   ├── controller/                  # REST Controllers (Auth, Project, Team)
│   │   ├── dto/                         # Data Transfer Objects & Summary DTOs
│   │   ├── model/                       # JPA Entities (User, Project, ApiKey, AuditLog, etc.)
│   │   ├── repository/                  # Spring Data JPA Repositories
│   │   ├── security/                    # JWT Filters, SecurityConfig, UserDetailsService
│   │   └── service/                     # Business Logic (Audit, Email, OTP, RateLimit, Team)
│   ├── src/main/resources/
│   │   └── application.yml              # Database, Mail, JWT, and Cache configuration
│   ├── pom.xml                          # Maven Dependencies & Build Configuration
│   └── secrets.properties               # Local Environment Secrets & DB Credentials
│
├── frontend/                            # Vanilla JS/CSS Zero-Knowledge Web App
│   ├── css/                             # Design System, Glassmorphism, Responsive Styles
│   ├── js/
│   │   ├── api.js                       # API Client with Bearer Token & Error Interceptors
│   │   ├── auth.js                      # Login, Registration, OTP Verification & Session Crypto
│   │   ├── crypto.js                    # Web Crypto API Module (PBKDF2, AES-256-GCM, RSA)
│   │   ├── dashboard.js                 # Project Dashboard Orchestration
│   │   ├── project.js                   # Secret Management, Versioning & Rollback UI
│   │   ├── teams.js                     # RBAC & Member Invitation Controller
│   │   ├── audit.js                     # Compliance Activity Log Viewer
│   │   └── theme-manager.js             # Theme & Accent Customizer
│   ├── server.js                        # Lightweight Node.js Static Server
│   ├── landing.html                     # Product Landing Page
│   ├── login.html                       # Authenticate to Vault
│   ├── register.html                    # Zero-Knowledge User Onboarding
│   ├── dashboard.html                   # Workspaces Overview
│   ├── project.html                     # Secrets Explorer & Version History
│   ├── teams.html                       # RBAC & Member Management
│   ├── audit.html                       # Forensic Audit Trail
│   └── settings.html                    # User Profile & Identity Settings
│
├── cli/                                 # Developer CLI Tool (`kv-cli`)
│   ├── bin/kv-cli.js                    # Executable Entrypoint (Commander.js)
│   ├── commands/                        # login, logout, status, run (Process Injection)
│   └── package.json                     # CLI Dependencies & NPM configuration
│
└── README.md                            # Comprehensive Documentation
```

---

## 🗄 Database Schema & ER Model

```sql
-- 1. Users Table
CREATE TABLE users (
    id BINARY(16) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    public_key TEXT,
    encrypted_private_key TEXT,
    created_at DATETIME
);

-- 2. Projects Table
CREATE TABLE projects (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    name VARCHAR(255) NOT NULL,
    tag VARCHAR(255),
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Project Members (RBAC) Table
CREATE TABLE project_members (
    id BINARY(16) PRIMARY KEY,
    project_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    role VARCHAR(50) NOT NULL, -- OWNER, ADMIN, MEMBER, VIEWER
    created_at DATETIME,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. API Keys Table (Stores only Ciphertext)
CREATE TABLE api_keys (
    id BINARY(16) PRIMARY KEY,
    project_id BINARY(16) NOT NULL,
    name VARCHAR(255) NOT NULL,
    service VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL, -- DEV, STAGING, PROD
    encrypted_value TEXT NOT NULL,
    iv VARCHAR(255) NOT NULL,
    expiry_date DATE,
    notes TEXT,
    created_at DATETIME,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- 5. API Key Versions (Immutable Historical Snapshots)
CREATE TABLE api_key_versions (
    id BINARY(16) PRIMARY KEY,
    api_key_id BINARY(16) NOT NULL,
    encrypted_value TEXT NOT NULL,
    iv VARCHAR(255) NOT NULL,
    version_number INT NOT NULL,
    created_at DATETIME,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
);

-- 6. Machine Tokens (CI/CD Programmatic Tokens)
CREATE TABLE machine_tokens (
    id BINARY(16) PRIMARY KEY,
    project_id BINARY(16) NOT NULL,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    token_prefix VARCHAR(50) NOT NULL,
    environment VARCHAR(50) NOT NULL,
    expiry_date DATETIME,
    created_at DATETIME,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- 7. Audit Logs Table (Compliance Tracking)
CREATE TABLE audit_logs (
    id BINARY(16) PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    ip_address VARCHAR(100),
    timestamp DATETIME NOT NULL
);
```

---

## 💻 Developer CLI (`kv-cli`) & Process Injection

The CLI enables developers to run processes with decrypted secrets injected straight into `process.env` without ever writing `.env` files to disk.

```bash
# 1. Install CLI locally / link
cd cli
npm link

# 2. Authenticate CLI session
kv-cli login

# 3. Check active session status
kv-cli status

# 4. Run an application with decrypted production secrets
kv-cli run --project <PROJECT_ID> --env prod -- npm start

# 5. Run in CI/CD pipeline using Machine Token:
kv-cli run --token mct_live_xyz... -- npm test

# 6. Terminate session and purge cached tokens
kv-cli logout
```

---

## 📡 REST API Endpoints Reference

### Authentication (`/auth`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/auth/salt?email={email}` | Returns user salt (or deterministic fake salt to prevent email enumeration) |
| `POST`| `/auth/otp/send` | Sends a 6-digit OTP code to email for verification |
| `POST`| `/auth/otp/verify` | Verifies OTP code before allowing registration or password reset |
| `POST`| `/auth/register` | Registers user with salt, hashed password, and key pairs |
| `POST`| `/auth/login` | Authenticates credentials and returns JWT + user cryptography metadata |
| `PUT` | `/auth/identity` | Provisions or upgrades asymmetric RSA public/private key pairs |
| `POST`| `/auth/logout` | Invalidates JWT and adds it to server-side Token Blacklist |
| `POST`| `/auth/forgot-password` | Initiates password recovery via email OTP |
| `POST`| `/auth/reset-password` | Resets password after OTP verification |
| `GET` | `/auth/me` | Fetches current user profile and public key |

### Projects & Secrets (`/api`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/projects` | High-performance aggregated list of projects with secret counts and alert indicators |
| `POST`| `/api/projects` | Creates a new project workspace |
| `DELETE`| `/api/projects/{id}` | Deletes project and cascades deletion to keys and members |
| `GET` | `/api/projects/{id}/keys` | Retrieves all ciphertext secrets and IVs for a project |
| `POST`| `/api/projects/{id}/keys` | Adds an encrypted secret (ciphertext + IV) |
| `PUT` | `/api/projects/{id}/keys/{keyId}` | Updates an encrypted secret and archives previous version snapshot |
| `DELETE`| `/api/projects/{id}/keys/{keyId}` | Deletes an API key and associated history |
| `GET` | `/api/keys/{keyId}/versions` | Lists historical versions of a key |
| `POST`| `/api/keys/{keyId}/rollback/{vId}`| Reverts key to selected historical version |
| `GET` | `/api/projects/{id}/tokens` | Lists active Machine Tokens |
| `POST`| `/api/projects/{id}/tokens` | Generates a new scoped Machine Token |
| `GET` | `/api/audit-logs` | Retrieves audit activity logs for compliance |

### Teams & RBAC (`/api/teams`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/teams/{projectId}/members` | Lists team members and their assigned roles |
| `POST`| `/api/teams/{projectId}/invite` | Invites a user to a project with a specific role |
| `PUT` | `/api/teams/{projectId}/members/{userId}/role` | Updates member role (`ADMIN`, `MEMBER`, `VIEWER`) |
| `DELETE`| `/api/teams/{projectId}/members/{userId}` | Removes a member from the project |
| `POST`| `/api/teams/{projectId}/leave` | Leaves a project workspace |

---

## 🛡 Security & Anti-Abuse Hardening

1. **Anti-User Enumeration (Deterministic Fake Salt):**
   When an unregistered email requests `/auth/salt`, the server derives a deterministic SHA-256 HMAC of the email with a pepper, returning a plausible 128-bit hex string so attackers cannot probe existing accounts.
2. **Bucket4j Distributed Rate Limiting:**
   Applies rate-limiting buckets per IP address and email on all authentication endpoints (`/auth/login`, `/auth/otp/send`, `/auth/register`) to thwart credential stuffing and brute-force attacks.
3. **Token Blacklist Service:**
   Active JWT tokens are blacklisted in memory upon logout until their expiration timestamp, preventing replay attacks if a token was captured.
4. **Dual Auth Support:**
   Supports both `Authorization: Bearer <JWT>` for CLI/API clients and `SameSite=Strict; HttpOnly` cookies for browser clients to prevent XSS credential theft.
5. **N+1 Query Prevention via JPA Projections:**
   The dashboard runs a single custom DTO projection query (`ProjectSummaryDTO`) to aggregate key counts and expiry alerts across all user projects, eliminating N+1 performance bottlenecks.

---

## 🚀 Local Setup & Running the Services

### Prerequisites
- **Java 17 LTS** (`java -version`)
- **Maven 3.8+** (`mvn -version`)
- **MySQL 8.0** running locally on port 3306
- **Node.js (v18+)** (`node -v`)

### 1. Database Setup
Create the database and configure user permissions in MySQL:
```sql
CREATE DATABASE keyvault_db;
CREATE USER 'DEV'@'localhost' IDENTIFIED BY 'Qwaszx@12304';
GRANT ALL PRIVILEGES ON keyvault_db.* TO 'DEV'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Backend Configuration
Ensure `backend/secrets.properties` contains:
```properties
DB_USERNAME=DEV
DB_PASSWORD=Qwaszx@12304
JWT_SECRET=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
RESEND_API_KEY=re_your_api_key_here
```

### 3. Start Backend Server
```bash
cd backend
mvn spring-boot:run
```
*Backend starts on `http://localhost:8080`.*

### 4. Start Frontend Server
```bash
node frontend/server.js
```
*Open `http://localhost:3000` in your web browser.*

### 5. Install & Test CLI
```bash
cd cli
node bin/kv-cli.js --help
```

---

## 🎯 Interview Cheatsheet & Architectural Highlights

If asked about this project during technical interviews, highlight these architectural points:

1. **Why Zero-Knowledge Architecture?**
   - *Traditional Secrets Managers (e.g. standard AWS Secrets Manager, Vault in standard mode)* decrypt on the server. If the server or database is compromised, all secrets are exposed.
   - *KeyVault* uses client-side encryption (`AES-256-GCM` + `PBKDF2`). The server only ever sees encrypted ciphertext and random IVs. Even with a full database dump, attackers cannot decrypt secrets without the user's master password.
2. **Why 2-Stage Key Derivation?**
   - To prevent the server from ever having the ability to derive the encryption key.
   - Stage 1 derives `Auth_Hash` for authentication; Stage 2 derives `Master_Key` for encryption. The backend only ever sees `BCrypt(Auth_Hash)`.
3. **How does Key Versioning work without decrypting on the server?**
   - Every update creates a new immutable `ApiKeyVersion` row storing the previous ciphertext and IV. Rollback simply updates the active pointer to the historical ciphertext — fully zero-knowledge!
4. **How does the CLI inject secrets safely?**
   - It fetches ciphertext, decrypts in RAM, and passes them as environment variables via `child_process.spawn(cmd, { env: { ...process.env, ...decryptedSecrets } })`. No temporary `.env` files are written to disk.
5. **How were performance and anti-abuse addressed?**
   - Avoided N+1 queries using JPA Aggregated Projections (`getProjectSummaries`).
   - Implemented Token Bucket rate limiting using `Bucket4j` and in-memory caching via `Caffeine`.
   - Prevented user enumeration using deterministic fake salt hashing.

---

## 📄 License
This project is open source and available under the [MIT License](LICENSE).
