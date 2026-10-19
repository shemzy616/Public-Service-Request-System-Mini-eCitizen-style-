# Huduma Murang'a — Public Service Request Portal
### County 021 | Murang'a County Government | ICT Intern Evaluation Project
> **Motto:** *"Kamũingĩ Koyaga Ndĩrĩ"* — Unity is Strength  
> **County Citizen Helpline:** `0119706796` | **Headquarters:** P.O. Box 52-10200, Murang'a

---

## 1. Executive Summary & Project Overview

**Huduma Murang'a** is a full-stack, enterprise-grade e-Government public service portal developed for the **Murang'a County Government (County Code 021)** ICT intern technical evaluation. 

The system modernizes the delivery of municipal public services by bridging Murang'a citizens with county technical departments. Citizens can submit service requests for infrastructure failures (water outages, broken streetlights, uncollected garbage, and road potholes), track ticket progress in real-time without login walls, receive automated email status notifications, and rate completed resolutions. 

County administrative staff and department heads access a centralized Command Dashboard equipped with real-time KPI metrics, department ticket routing, user directory account controls, and an immutable audit trail.

---

## 2. System Architecture & Tech Stack

The portal adheres to a clean, decoupled **API-First Single-Page Application (SPA)** architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CLIENT LAYER (Modern Web Browser & Mobile)           │
│  React 18 SPA · Mobile-First Responsive Layout (iOS & Android Native)  │
│  Tailwind CSS (Apple Liquid Glass Material & Continuous Photo Mosaic)  │
│  Direct Mobile Camera Capture · Real-Time Password Checklist & Stepper │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ JSON API Requests / Multipart Form
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   APPLICATION SERVER (Python / Flask)                  │
│  Flask 3.0 · WSGI Factory Pattern · Blueprints (/api/auth & /api)      │
│  python-dotenv (.env) · Werkzeug PBKDF2/scrypt Security · Sliding Limiter│
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │                                 │
                   ▼ (Parameterized SQL Queries)     ▼ (Non-blocking Threading)
┌────────────────────────────────────┐  ┌────────────────────────────────┐
│      PERSISTENCE (SQLite3)         │  │   NOTIFICATION ENGINE (SMTP)   │
│  portal.db / muranga_portal.db     │  │   Gmail SSL SMTP (Port 465/587)│
│  Indexes · DDL Constraints · Audit │  │   HTML Ticket & OTP Dispatches │
└────────────────────────────────────┘  └────────────────────────────────┘
```

### Component Breakdown
- **Backend Framework:** Python 3.10+ / Flask 3.0 utilizing the Application Factory pattern (`create_app()`).
- **Architecture Modularity:** Clean Flask Blueprints (`auth_bp` for authentication and `requests_bp` for service ticket lifecycles).
- **Frontend SPA Shell:** React 18, Babel standalone JSX, and Tailwind CSS. Zero `node_modules` or complex build step required for deployment simplicity.
- **Mobile-First Responsive Engineering:**
  - Viewport-fit cover (`width=device-width, initial-scale=1.0, viewport-fit=cover`) and zero horizontal scrolling on 360px–390px screens.
  - Auto-zoom prevention: Minimum font size 16px (`text-base sm:text-sm`) with 44px touch targets across all form controls and selects.
  - On-site mobile camera capture with native OS photo sheet invocation (`accept="image/png,image/jpeg,image/webp"`).
  - Bounded viewport modals with internal momentum scrolling and 2-column mobile tab navigation.
- **Visual Design System:** Signature iOS-inspired **Liquid Glass (Vibrant Frosted Material)** surfaces (`bg-white/85 backdrop-blur-2xl backdrop-saturate-180 border border-white/60 shadow-[0_12px_40px_rgba(0,0,0,0.15),inset_0_1px_1px_rgba(255,255,255,0.9)]`) anchored by a continuous Translucent Emerald Photo Mosaic featuring 5 authentic Murang'a County landmarks.
- **Database Engine:** SQLite3 with foreign key enforcement (`PRAGMA foreign_keys = ON`), B-tree indexes, atomic transaction context managers (`with conn:`), and automatic first-run seeding.
- **Asynchronous Email Notification Engine:** Multi-threaded Python daemon workers utilizing `smtplib.SMTP_SSL` / `smtplib.SMTP` for non-blocking email delivery.

---

## 3. Key Features & Murang'a Evaluation Rubric Alignment

| Rubric Criterion | Implementation & Feature Highlights |
| :--- | :--- |
| **1. Citizen Portal & Service Requests** | • Public Ticket ID Lookup (`MCG-021-2026-XXXX`) with one-click Clear search input.<br>• One-click Clipboard Copy (`CopyTicketButton`) with tactile visual feedback across all ticket surfaces.<br>• Service Request Submission with optional JPEG/PNG photo evidence.<br>• 3-Step Visual Progress Stepper (`Pending` ➔ `In Progress` ➔ `Resolved`).<br>• Citizen Satisfaction Rating (`1` to `5` Stars) on resolved tickets.<br>• Ticket dismissal / clean dashboard management. |
| **2. Automated County Department Routing** | • Sub-county concession mapping across all 7 sub-counties (Gatanga, Kandara, Kangema, Kigumo, Kiharu, Maragua, Mathioya).<br>• Automatic routing to **MUWASCO**, **Gatamathi**, **Kahuti Water**, **Energy & Electrical Unit**, **Environment & Sanitation**, and **Roads & Infrastructure**. |
| **3. Security Controls & Defense-in-Depth** | • Cryptographically salted password hashing via Werkzeug.<br>• Interactive real-time Password Requirements Checklist & Visibility toggles.<br>• In-memory sliding-window IP rate limiter (`10` requests / `60s`).<br>• Magic-byte file upload validation (strictly verifies true JPEG/PNG headers).<br>• Inverted IDOR ownership verification (`user_id == session['user_id']`).<br>• OWASP CSV formula injection defense (escapes `=`, `+`, `-`, `@`). |
| **4. County Admin Command Dashboard** | • Real-time KPI Metric cards (`Total Requests`, `Pending`, `In Progress`, `Resolved`, `Satisfaction Rate`).<br>• Interactive request filtering by status, category, sub-county, and keyword.<br>• Status transitions with mandatory internal remarks.<br>• Citizen Directory with one-click account suspension / reactivation.<br>• Sanitized CSV Audit Export for county reporting. |
| **5. Live Notification Engine** | • Self-service 6-digit OTP password reset with 10-minute expiry.<br>• Branded, responsive HTML email dispatches upon ticket submission and resolution.<br>• Graceful async threading fallback: failures never degrade user interface performance. |
| **6. Mobile-First Field Usability** | • 100% responsive across 360px–390px mobile screens (`viewport-fit=cover`, zero horizontal overflow).<br>• Camera Evidence Capture: Direct invocation of native smartphone camera/gallery.<br>• Zero-Zoom form inputs (`16px` mobile font threshold) and `44×44px` minimum touch targets.<br>• Viewport-bounded modals with internal scrolling and 2-column mobile tab navigation.<br>• Swipeable admin tables and one-tap Helpline dialer (`tel:0119706796`). |

---

## 4. Automated Department Routing Matrix

When a citizen files a request, the server automatically resolves the ticket to the exact technical unit based on category and sub-county:

| Service Category | Target Sub-County | Assigned Technical Unit |
| :--- | :--- | :--- |
| **Water & Sewerage** | Kiharu, Maragua | **MUWASCO Technical Team** |
| **Water & Sewerage** | Mathioya, Kangema | **Gatamathi Water Team** |
| **Water & Sewerage** | Kigumo | **Kahuti Water Technical Unit** |
| **Water & Sewerage** | Gatanga, Kandara | **Gatanga Community Water Unit** |
| **Streetlight & Electrical** | All 7 Sub-Counties | **Murang'a County Energy & Electrical Unit** |
| **Garbage & Sanitation** | All 7 Sub-Counties | **Environment & Public Health Directorate** |
| **Roads & Drainage** | All 7 Sub-Counties | **Directorate of Roads, Transport & Infrastructure** |

---

## 5. Security & Privacy Architecture

1. **Password Security:**
   - Werkzeug PBKDF2/scrypt cryptographic salting and hashing.
   - Client-side real-time password checklist enforcing: Minimum 6 characters, uppercase, lowercase, numeric, and special character criteria.
2. **Session Hardening:**
   - Flask session cookies configured with `HttpOnly=True` (guards against XSS cookie theft) and `SameSite=Lax` (guards against CSRF).
   - Session identifiers regenerated upon login to prevent session fixation.
3. **Magic-Byte File Upload Validation:**
   - Uploaded files are checked against magic signature bytes (`\xFF\xD8\xFF` for JPEG, `\x89PNG\r\n\x1a\n` for PNG).
   - File extensions are sanitized using `werkzeug.utils.secure_filename` with UUID4 prefixes.
4. **Data Protection Act (DPA) Compliance:**
   - The unauthenticated public ticket tracking endpoint (`/api/requests/track/<ticket_id>`) strictly omits citizen PII (name, email, phone number).
5. **OWASP CSV Injection Defense:**
   - Data exported via `/api/requests/export` prepends a single quote (`'`) to any cell beginning with `=`, `+`, `-`, or `@`.
6. **Immutable Audit Trail:**
   - Every administrative status change records an append-only entry in `audit_logs` storing timestamp, actor ID, IP address, and remarks.

---

## 6. Mobile-First Usability & Field Operations Engineering

Because the majority of Murang'a County residents report public service issues on location from their smartphones, the interface is engineered for 100% field usability across mobile viewports:

1. **Zero-Horizontal Overflow & Safe-Area Configuration:**
   - `<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">` paired with strict `overflow-x-hidden` containers eliminates unintended horizontal page drifting on 360px–390px screens.
2. **Auto-Zoom Prevention on Mobile Browsers:**
   - Mobile Safari (iOS) and Chrome (Android) automatically zoom and distort layouts if inputs have font sizes smaller than `16px`. All text inputs, selectors, and textareas use `text-base sm:text-sm` (16px on mobile, 14px on desktop) with `min-h-[44px]` touch targets.
3. **On-Site Camera Evidence Capture:**
   - The photo upload component provides an interactive dropzone button (`min-h-[48px]`) with `accept="image/png,image/jpeg,image/webp"` that triggers the device's native camera or gallery sheet on tap, with instant preview and client-side 5MB size guards.
4. **Bounded Viewport Modals & Mobile Tab Navigation:**
   - The **Civic Profile Modal** (`ProfileModal`) is capped at `max-h-[calc(100dvh-1.5rem)] sm:max-h-[90vh]` with pinned headers and internal momentum scrolling (`overflow-y-auto overscroll-contain`).
   - The tab switcher uses an exact 2-column grid (`grid-cols-2`) with responsive labels (*"Details"* & *"Security"* on mobile screens `<640px`, expanding to full labels on desktop), completely preventing modal stretching or overflow.
5. **Touch-Optimized Admin Operations:**
   - Command Dashboard tabs support horizontal swipe scrolling without intrusive scrollbars (`overflow-x-auto no-scrollbar`).
   - Request and Audit tables feature full-bleed mobile scrolling (`-mx-4 sm:mx-0 rounded-none sm:rounded-2xl border-y sm:border`).
6. **One-Tap County Helpline Dialer:**
   - The footer helpline is linked with `<a href="tel:0119706796">` allowing citizens in urgent situations to call county dispatch directly from their phone with one tap.
7. **One-Click Ticket ID Clipboard Copy (`CopyTicketButton`):**
   - Implemented across all ticket representations (Citizen Request cards, Tracking result card, Public 311 modal, Post-submission confirmation receipt, and Admin queue).
   - Features modern `navigator.clipboard` integration with safe textarea fallback and instantaneous visual feedback (*"Copied!"* with checkmark icon).
8. **Interactive Search Clear & Reset Action:**
   - The Ticket Tracker search input features an instant clear button (`✕`) whenever text is entered, allowing citizens to wipe the search query and dismiss tracked results with one tap so tickets never remain stuck.

---

## 7. Pre-Seeded Evaluator Test Credentials

Evaluators can click the **Quick Evaluator Demo Login** buttons on the login page for instant 1-click access, or manually enter the pre-seeded credentials:

| Role | Email Address | Password | Permissions & Scope |
| :--- | :--- | :--- | :--- |
| **County Admin** | `admin@muranga.go.ke` | `Admin@2026` | Full administrative access, KPI dashboard, status updates, citizen directory management, CSV exports. |
| **Citizen (Demo)** | `mary.wanjiku@citizen.ke`<br>*(or `wanjiku@gmail.com`)* | `Citizen@2026` | Submit service requests, view personal tickets, progress stepper tracking, rate resolved services. |

---

## 8. Step-by-Step Installation & Setup Guide

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- Git and a modern browser (Google Chrome, Microsoft Edge, Safari, Mozilla Firefox).

### Step 1: Clone or Open the Repository
```bash
cd "c:/Users/shemm/OneDrive/Desktop/Muranga project assignment"
```

### Step 2: Create and Activate a Python Virtual Environment
**On Windows (PowerShell):**
```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the sanitized environment template to create your `.env` file:
```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```
Ensure `.env` contains your runtime credentials:
```env
FLASK_SECRET_KEY=replace-with-a-secure-random-secret-key-2026
SMTP_EMAIL=your-county-service-email@gmail.com
SMTP_APP_PASSWORD=your-16-character-app-password
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=465
HELPLINE_NUMBER=0119706796
DATABASE_URL=portal.db
```
*(Note: Safe fallback defaults exist in code, allowing the portal to boot out-of-the-box even if `.env` is omitted).*

### Step 5: Start the Application Server
```bash
python app.py
```
Or with the Windows Python launcher:
```bash
py -3 app.py
```

### Step 6: Access the Portal
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## 9. RESTful API Reference

### Authentication Endpoints (`/api/auth`)
| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Public | Register a new citizen account. |
| `POST` | `/api/auth/login` | Public | Authenticate user and initiate session cookie. |
| `POST` | `/api/auth/logout` | Authenticated | Terminate session. |
| `GET` | `/api/auth/me` | Authenticated | Inspect current authenticated session context. |
| `POST` | `/api/auth/forgot-password` | Public | Send 6-digit OTP verification code to registered email. |
| `POST` | `/api/auth/reset-password` | Public | Verify OTP code and reset account password. |
| `PATCH` | `/api/auth/profile` | Authenticated | Update full name, phone, or sub-county. |
| `POST` | `/api/auth/change-password` | Authenticated | Change password with current password verification. |

### Service Request Endpoints (`/api`)
| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/requests` | Authenticated | List service requests (scoped to user or all for admin). |
| `POST` | `/api/requests` | Citizen | Submit new service ticket with multipart photo upload. |
| `PATCH` | `/api/requests/<id>/status` | Admin | Update status (`Pending`, `In Progress`, `Resolved`). |
| `PATCH` | `/api/requests/<id>/rate` | Citizen (Owner) | Submit 1–5 star rating for resolved ticket. |
| `DELETE`| `/api/requests/<id>` | Citizen (Owner) | Clear / dismiss resolved ticket from user dashboard. |
| `GET` | `/api/requests/track/<ticket_id>`| Public | Zero-login public status tracker (PII-free). |
| `GET` | `/api/analytics` | Admin | Real-time KPI summaries and category distributions. |
| `GET` | `/api/requests/export` | Admin | Sanitized CSV spreadsheet export. |
| `GET` | `/api/admin/users` | Admin | List all registered citizen and administrator accounts. |
| `PATCH` | `/api/admin/users/<id>/toggle-status`| Admin | Suspend or reactivate user account. |

---

## 10. Project Directory Structure

```
├── app.py                     # Flask application factory, routes, and error handlers
├── database.py                # Schema DDL, SQLite connection factory, and routing logic
├── auth.py                    # Authentication Blueprint, RBAC, sliding rate limiter, OTP
├── requests_api.py            # Service requests Blueprint, analytics, CSV export, email dispatch
├── requirements.txt           # Production dependencies (Flask, Werkzeug, python-dotenv)
├── .env                       # Active runtime environment secrets
├── .env.example               # Sanitized environment template for version control
├── portal.db                  # Primary SQLite database file
├── muranga_portal.db          # Database mirror / backup
├── static/                    # Static assets
│   ├── logo.png               # Official Murang'a County seal / favicon
│   ├── muranga  roads.jpg     # Hero mosaic photo: Road infrastructure
│   ├── Muranga County Central Province Tea Farming Kenyan.jpg # Hero mosaic: Tea farming
│   ├── muranga tea.jpg        # Hero mosaic photo: Agriculture
│   ├── town muranga.jpg       # Hero mosaic photo: Urban landscape
│   ├── water mur.jpg          # Hero mosaic photo: Water resources
│   └── uploads/               # Citizen photo evidence upload storage
└── templates/
    └── index.html             # React 18 SPA, Tailwind Liquid Glass styling, and icons
```

---

## 11. Verification & Quality Assurance

- **HTTP Status Check:** Tested with `curl` on `http://127.0.0.1:5000/` returning `HTTP 200 OK`.
- **Favicon Resolution:** Tested `/static/logo.png` returning `HTTP 200 OK`.
- **Database Consistency:** Verified tables (`users`, `service_requests`, `audit_logs`) and indexes load without error.
- **Mobile-First Responsiveness:** Verified on 360px–414px mobile viewports (zero horizontal overflow, auto-zoom prevention, touch targets ≥ 44px, bounded scrollable modals).
- **Cross-Platform Compatibility:** Tested on Windows with Python 3.14 / PowerShell and compatible with Linux/macOS environments.

---

