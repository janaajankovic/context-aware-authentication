# RiskAuth: Risk-Based Context-Aware Authentication

A distributed microservice system for dynamic user authentication based on contextual risk evaluation. Instead of relying solely on static credentials, RiskAuth evaluates the hardware and network context in real-time (IP address, geolocation, User-Agent, and login history) to assign a risk score. Based on the score, the system dynamically allows access, requires Multi-Factor Authentication (MFA), or blocks the request.

## Specification coverage

| Requirement | Where |
| :--- | :--- |
| **Context Extraction** | `auth-service` extracts network and device data from the HTTP request headers (`X-Forwarded-For`, `User-Agent`). |
| **Risk Evaluation Engine** | `risk-engine` (Python/FastAPI) evaluates context against historical data and geolocation APIs, returning a risk score (0.0 to 1.0). |
| **Adaptive MFA (TOTP)** | `auth-service` generates temporary Pre-Auth tokens; requires Google Authenticator validation if risk score > threshold. |
| **Rate Limiting & Brute-force protection** | `auth-service` uses a `Redis` in-memory cache to track failed attempts per IP and returns HTTP 429 instantly. |
| **Centralized Security Monitoring** | `Logstash` asynchronously collects audit logs from microservices and pushes them to `Elasticsearch`, visualized in `Kibana`. |
| **REST Microservices** | Spring Boot backend, Python Risk Engine, and Angular client communicating via REST APIs. |

## What runs where

| Component | Port | Needs | Role |
| :--- | :--- | :--- | :--- |
| **RiskAuth UI** | `4200` | Node.js | Angular client application (User Interface). |
| **Auth Service** | `8080` | PostgreSQL, Redis | Spring Boot backend handling core authentication, JWT issuance, and MFA. |
| **Risk Engine** | `8000` | - | Python FastAPI service for policy evaluation, scoring, and anomaly detection. |
| **PostgreSQL** | `5432` | - | Relational database storing users, encrypted MFA secrets, and login history. |
| **Redis** | `6379` | - | In-memory cache for Rate Limiting and fast session tracking. |
| **Elasticsearch** | `9200` | - | Search and analytics engine for storing security logs. |
| **Logstash** | `50000` | Elasticsearch | Data processing pipeline ingesting audit logs from the Auth Service. |
| **Kibana** | `5601` | Elasticsearch | Dashboard for real-time visualization of security events and anomalies. |

---

## Prerequisites

*   **JDK 21+** (for building the Spring Boot Auth Service)
*   **Python 3.10+** (for the FastAPI Risk Engine)
*   **Node.js 20+** and `npm` (for the Angular Dashboard only)
*   **Docker and Docker Compose** (for spinning up PostgreSQL, Redis, and the ELK stack)

---

## Setup & Run

### 1. Start the infrastructure
Run the provided Docker Compose file to start the database, cache, and monitoring stack:
```bash
docker-compose up -d
2. Start the Risk Engine (Python)
Navigate to the risk-engine directory, install requirements, and run the FastAPI server:
```
```Bash
cd risk-engine
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
3. Start the Auth Service (Java)
Navigate to the auth-service directory and run the Spring Boot application:
```
```Bash
cd auth-service
./mvnw spring-boot:run
4. Start the Client UI (Angular)
Navigate to the frontend directory, install dependencies, and start the development server:
```
```Bash
cd frontend
npm install
ng serve
Access the application at http://localhost:4200.
```

Application Previews & Workflows
1. Authentication & Rate Limiting
The system actively monitors failed attempts and enforces strict rate limiting via Redis to prevent Credential Stuffing and Brute-force attacks.
<img width="1272" height="787" alt="Screenshot 2026-09-05 144816" src="https://github.com/user-attachments/assets/6dc2039f-8a4c-4454-948f-428535b922cf" />

2. Adaptive Multi-Factor Authentication
If the Python Risk Engine detects anomalous behavior (e.g., unusual location or impossible travel speed), it mandates a secondary TOTP verification.
<img width="731" height="704" alt="Screenshot 2026-09-06 182106" src="https://github.com/user-attachments/assets/63d5a509-505b-4f3a-adf5-0cd96cd86ec5" />

Users can configure their MFA device securely using dynamically generated QR codes.
<img width="635" height="526" alt="Screenshot 2026-09-06 005802" src="https://github.com/user-attachments/assets/6eb9b88a-6fbc-4522-bca4-6c69a280c06f" />

3. User Dashboard & Context Visibility
Users have full transparency over their active session context and a complete history of their login attempts.
<img width="1819" height="869" alt="Screenshot 2026-09-07 171735" src="https://github.com/user-attachments/assets/ac1579ef-6cd1-408c-b56f-64b3cf8eceeb" />

4. Security Monitoring & Analytics (ELK Stack)
All authentication events are streamed to Kibana for real-time administrative oversight, allowing for immediate threat detection.

Authentication Outcomes Distribution:
<img width="1790" height="663" alt="Screenshot 2026-09-05 003121" src="https://github.com/user-attachments/assets/6538b872-9317-4673-923b-844ab64237be" />

Temporal Distribution of Security Events by Criticality:
<img width="1908" height="670" alt="Screenshot 2026-09-05 001219" src="https://github.com/user-attachments/assets/96493554-499a-442d-8dcb-d722cedb2e3b" />

5. Automated Attack Simulation
The project includes a custom Python simulation script to validate system resilience against Credential Stuffing. The output demonstrates how Redis successfully drops malicious traffic (Status 429 BLOKIRANO) with sub-50ms latency, protecting the main relational database.
<img width="1051" height="882" alt="Screenshot 2026-09-06 233936" src="https://github.com/user-attachments/assets/f890e27f-0731-4d30-8c67-b0a963b4d420" />
