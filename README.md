# SentinelX

> **IBM SkillsBuild / Bootcamp Submission**
> Cybersecurity Threat Detection and Monitoring Dashboard
> Built with Java 21 · Spring Boot · Vanilla JavaScript

---

## Project Summary

SentinelX is a beginner-friendly cybersecurity operations dashboard that detects and visualises synthetic security threats in real time. It was built as a portfolio project for the IBM bootcamp to demonstrate practical skills in backend development, REST API design, automated testing, and frontend integration.

The dashboard monitors a stream of synthetic security events, automatically detects brute-force login attacks using configurable rules, raises actionable alerts with plain-English explanations, and presents everything in a clean dark-themed UI.

> **Safety notice:** SentinelX runs entirely on your local machine and uses only synthetic (made-up) data.
> It does not scan real networks, collect real credentials, or send data to any external service.
> All IP addresses are from the RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`) — they are never routed on the real internet.

---

## Problem It Solves

Security teams need to monitor large volumes of events and quickly spot threats. A real SOC (Security Operations Centre) dashboard does exactly this — it aggregates logs, runs detection rules, and surfaces actionable alerts. SentinelX recreates this workflow at a beginner scale using:

- **Synthetic events** that mirror real attack patterns (brute-force, port scans, privilege escalation)
- **Automated detection** that flags suspicious behaviour based on configurable rules
- **Clear alert explanations** that tell a defender exactly what happened and what to do next

---

## Features

| Feature | Description |
|---|---|
| Live dashboard | Summary cards showing total events and counts by severity — flip on hover to reveal descriptions |
| Brute-force detection | Flags source IPs with ≥ 5 failed logins within 10 minutes (both values configurable) |
| Alert explanations | Plain-English description of each threat and a recommended defensive action |
| Event filtering | Filter the events table by severity (LOW / MEDIUM / HIGH / CRITICAL) and event type |
| Health endpoint | `GET /api/health` confirms the service is running |
| 43 automated tests | Unit tests for service logic and MockMvc tests for every REST endpoint |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.3.5 |
| Build tool | Maven |
| Frontend | HTML5, CSS3, Vanilla JavaScript (no external libraries or CDNs) |
| Testing | JUnit 5, AssertJ, Spring MockMvc |
| Data storage | In-memory (no database required) |

---

## Dashboard Preview

> **How to see it:** Follow the [Getting Started](#getting-started) steps below, then open `http://localhost:8085` in your browser.

The dashboard shows:
- **Stat cards** — total events, active alerts, and counts by severity. Hover any card to flip it and see what the number means.
- **Active Alerts section** — brute-force alerts with IP address, targeted accounts, explanation, and recommended action.
- **Security Events table** — all 38 synthetic events, newest first, with severity badges and live filter dropdowns.

---

## Project Structure

```
SentinelX/
├── pom.xml                                  ← Maven build configuration
├── README.md
├── .gitignore
└── src/
    ├── main/
    │   ├── java/com/sentinelx/
    │   │   ├── SentinelXApplication.java    ← entry point
    │   │   ├── model/
    │   │   │   ├── SecurityEvent.java       ← event data shape (immutable record)
    │   │   │   └── Alert.java               ← alert data shape (immutable record)
    │   │   ├── service/
    │   │   │   ├── EventService.java        ← in-memory synthetic event store
    │   │   │   └── DetectionService.java    ← brute-force detection rule
    │   │   └── controller/
    │   │       └── DashboardController.java ← REST API (4 endpoints)
    │   └── resources/
    │       ├── application.properties       ← configurable threshold & time window
    │       └── static/
    │           ├── index.html               ← single-page dashboard UI
    │           ├── style.css                ← dark navy/emerald theme, flip cards
    │           └── app.js                   ← fetch() calls, rendering, filters
    └── test/
        └── java/com/sentinelx/
            ├── service/
            │   ├── EventServiceTest.java        ← 12 tests
            │   └── DetectionServiceTest.java    ← 17 tests
            └── controller/
                └── DashboardControllerTest.java ← 14 tests
```

---

## Getting Started

### Prerequisites

- **Java 21** — [download from Adoptium](https://adoptium.net/)
- **IntelliJ IDEA** (Community or Ultimate) — free at [jetbrains.com](https://www.jetbrains.com/idea/)

No separate Maven installation is needed — IntelliJ includes Maven.

### Run in IntelliJ IDEA

1. Open IntelliJ IDEA → **File → Open** → select the `SentinelX` folder
2. When prompted, click **"Load Maven Project"**
3. Wait for dependencies to download (progress bar, bottom right — ~60 seconds first time)
4. Open `src/main/java/com/sentinelx/SentinelXApplication.java`
5. Click the green ▶ button next to `main()` → **Run 'SentinelXApplication'**
6. Wait for: `Started SentinelXApplication in X seconds`
7. Open your browser: **http://localhost:8085**

### Run the Tests

In IntelliJ: right-click the `src/test` folder → **Run 'All Tests'**

Expected result:
```
Tests run: 43, Failures: 0, Errors: 0, Skipped: 0  ✅
```

### Run from the Terminal (if Maven is on your PATH)

```bash
mvn spring-boot:run
```

Then open **http://localhost:8085**.

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | `{"status":"UP","application":"SentinelX"}` |
| GET | `/api/events` | All synthetic security events, newest first |
| GET | `/api/events?severity=HIGH` | Filter by severity: `LOW` `MEDIUM` `HIGH` `CRITICAL` |
| GET | `/api/events?type=LOGIN_FAILURE` | Filter by type: `LOGIN_FAILURE` `LOGIN_SUCCESS` `PORT_SCAN` `PRIVILEGE_ESCALATION` `SUSPICIOUS_TRAFFIC` |
| GET | `/api/alerts` | Active brute-force alerts with explanations |
| GET | `/api/summary` | Total event count, alert count, per-severity breakdown |

Invalid filter values return `HTTP 400` with a descriptive error message.

---

## Configuration

Edit `src/main/resources/application.properties` to tune the detection rule — no code changes needed:

```properties
# How many failed logins from the same IP triggers an alert
sentinelx.detection.brute-force.threshold=5

# How far back (in minutes) to look when counting failures
sentinelx.detection.brute-force.window-minutes=10
```

Restart the application after changing these values.

---

## How the Detection Works

```
All events
    │
    ▼  keep only: LOGIN_FAILURE events within the time window
    │
    ▼  group by: source IP address
    │
    ▼  for each IP: if count >= threshold → raise Alert
```

1. On every `/api/alerts` request, `DetectionService` reads all events from `EventService`
2. It filters to `LOGIN_FAILURE` events whose timestamp is within the configured window
3. Events are grouped by source IP using a `Map<String, List<SecurityEvent>>`
4. Any IP with **≥ threshold** failures produces one `Alert`
5. The alert includes the IP, targeted usernames, a plain-English explanation, and a recommended action

Successful logins are completely ignored by the rule.

---

## Synthetic Data

All 38 events are generated at startup by `EventService`. No real user data or network activity is involved.

| Pattern | Purpose |
|---|---|
| 6 `LOGIN_FAILURE` from `192.0.2.42` within 9 min | Triggers the brute-force alert |
| 3 `LOGIN_FAILURE` from `198.51.100.7` | Below threshold — no alert fires |
| 2 failures from `192.0.2.42` at −29/−30 min | Outside the time window — ignored |
| Multiple `LOGIN_SUCCESS` events | Normal behaviour baseline |
| `PORT_SCAN`, `PRIVILEGE_ESCALATION`, `SUSPICIOUS_TRAFFIC` | Dashboard variety |

---

## Testing Approach

| Test class | Count | What it covers |
|---|---|---|
| `EventServiceTest` | 12 | Data loads, unique IDs, severity filter, type filter, combined filter, sort order, defensive copy |
| `DetectionServiceTest` | 17 | Alert fires at threshold, above threshold, below threshold, empty list, out-of-window events, boundary event, grouping by IP, successful logins ignored, alert content accuracy |
| `DashboardControllerTest` | 14 | HTTP 200/400 responses, JSON structure, filter params, case-insensitive input, alert fields, summary counts |

All tests run without a database or external service. `DetectionServiceTest` and `EventServiceTest` create their objects directly (`new EventService()`) — no Spring context, very fast. `DashboardControllerTest` uses `@WebMvcTest` with `MockMvc`.

---

## What I Learned

- **Spring Boot fundamentals** — how `@RestController`, `@Service`, `@Value`, and auto-configuration work together
- **Layered architecture** — separating data, business logic, and API concerns into distinct classes
- **REST API design** — proper HTTP status codes, query parameter validation, and JSON responses
- **JUnit 5 testing** — writing isolated unit tests without a Spring context, and MockMvc tests for the web layer
- **Detection logic** — implementing a time-windowed, IP-grouped brute-force rule and making it configurable
- **Frontend integration** — calling a backend API with `fetch()`, rendering dynamic HTML, and handling error states safely
- **Cybersecurity concepts** — brute-force attacks, severity levels, alert triage, and defensive recommendations

---

## Safety and Ethics

- All data is synthetic and generated in code — no real users, IPs, or credentials
- The application makes no outbound network calls
- IP addresses use RFC 5737 documentation ranges, which are never routed on the real internet
- No secrets, passwords, or sensitive configuration are stored anywhere in the project
- The frontend escapes all server-supplied text before inserting it into the DOM

---

*Built for the IBM SkillsBuild Bootcamp — Java & Cybersecurity track.*

---

## IBM SkillsBuild Submission Files (BharatCares)

| File | Description |
|---|---|
| `GunjanSaini_SentinelX.ipynb` | Python Jupyter Notebook — synthetic events, brute-force detection, charts |
| `requirements.txt` | Python dependencies (`pandas`, `matplotlib`) |
| `GunjanSaini_ProjectReport.docx` | Full project report |
| `README.md` | This file |

### Run the Python Notebook

**Prerequisites:** Python 3.9+, Jupyter Notebook or VS Code with Jupyter extension.

```bash
# Install dependencies
pip install -r requirements.txt

# Open the notebook
jupyter notebook GunjanSaini_SentinelX.ipynb
```

Then run all cells top to bottom (**Kernel → Restart & Run All**).

The notebook will:
1. Generate 38 synthetic security events
2. Apply the brute-force detection rule
3. Display the events table and active alerts
4. Show three charts: events by severity, events by type, top active IPs

