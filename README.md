# Secure Java App — CI/CD Security Pipeline

A Spring Boot REST API demonstrating a full DevSecOps pipeline with
Jenkins, GitHub, CodeQL (SAST), IAST, and DAST (OWASP ZAP).

---

## Project Structure

```
secure-java-app/
├── src/
│   ├── main/java/com/secureapp/
│   │   ├── SecureApplication.java       # Entry point
│   │   ├── SecurityConfig.java          # Spring Security + JWT filter
│   │   ├── model/User.java              # JPA entity
│   │   ├── repository/UserRepository.java
│   │   ├── service/
│   │   │   ├── UserService.java         # Business logic + UserDetailsService
│   │   │   └── JwtService.java          # Token generation & validation
│   │   └── controller/
│   │       ├── AuthController.java      # POST /api/auth/register & /login
│   │       ├── UserController.java      # GET /api/users/me & /api/users
│   │       └── GlobalExceptionHandler.java
│   └── test/java/com/secureapp/
│       ├── UserServiceTest.java         # Unit tests (Mockito)
│       └── AuthFlowIT.java              # Integration tests (IAST stage)
├── .codeql/codeql-config.yml            # CodeQL query config
├── zap/zap-rules.conf                   # OWASP ZAP tuning
├── Dockerfile                           # Multi-stage build
├── Jenkinsfile                          # Full pipeline definition
└── pom.xml
```

---

## API Endpoints

| Method | Endpoint              | Auth     | Description            |
|--------|-----------------------|----------|------------------------|
| POST   | /api/auth/register    | None     | Register new user      |
| POST   | /api/auth/login       | None     | Login, returns JWT     |
| GET    | /api/users/me         | JWT      | Current user profile   |
| GET    | /api/users            | JWT+ADMIN| List all users         |
| GET    | /api/users/{id}       | JWT+ADMIN| Get user by ID         |
| GET    | /actuator/health      | None     | Health check (for ZAP) |

---

## Running Locally

```bash
# Build and run
mvn clean package -DskipTests
java -jar target/secure-java-app-1.0.0.jar

# Register a user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Password1!"}'

# Login and get token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Password1!"}'

# Use the token
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer <token>"
```

---

## Pipeline Setup Steps

### 1. GitHub Repository
- Push this project to a GitHub repo.
- Go to **Settings → Webhooks → Add webhook**
  - Payload URL: `http://<jenkins-host>/github-webhook/`
  - Content type: `application/json`
  - Trigger on: **Push** and **Pull requests**

### 2. Jenkins Setup
Install these plugins:
- GitHub Integration Plugin
- Pipeline Plugin
- HTML Publisher Plugin
- Credentials Binding Plugin

Add credentials in **Manage Jenkins → Credentials**:
- `jwt-secret` — Secret text, your JWT signing key (min 32 chars)
- `iast-api-key` — Secret text, from your IAST vendor dashboard

Create a **Pipeline job**:
- Source: Pipeline script from SCM → Git → your repo URL
- Branch: `*/main`
- Script path: `Jenkinsfile`

### 3. CodeQL Setup
Install the CodeQL CLI on your Jenkins agent:
```bash
# Download from https://github.com/github/codeql-action/releases
wget https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
tar xzf codeql-bundle-linux64.tar.gz -C /opt
export PATH=$PATH:/opt/codeql
```

### 4. IAST Agent Setup
Download your vendor's Java agent JAR to `/opt/iast/agent.jar` on the Jenkins agent.
Supported vendors: Contrast Security, Seeker, HCL AppScan, Hdiv.

Update `Jenkinsfile` env vars:
```groovy
IAST_SERVER_URL = "http://your-iast-server:8090"
IAST_API_KEY    = credentials('iast-api-key')
```

### 5. DAST — OWASP ZAP
ZAP runs as a Docker container — no installation needed, just Docker on the agent.
```bash
# Test locally:
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t http://localhost:8080 \
  -c zap/zap-rules.conf \
  -r zap/zap-report.html
```

---

## How Each Tool Catches Different Vulnerabilities

| Tool    | When it runs        | What it finds                              |
|---------|---------------------|--------------------------------------------|
| CodeQL  | On source code      | SQL injection, XSS, auth flaws, path traversal |
| IAST    | During test traffic | Real runtime data flows, taint tracking    |
| ZAP     | On running app      | HTTP headers, auth, OWASP Top 10 via HTTP  |

All three are complementary — SAST has no false negatives on code patterns,
IAST catches what only appears at runtime, DAST validates from the attacker's view.
