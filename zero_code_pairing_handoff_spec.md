# KyRecovery Server: Zero-Code Product Pairing & Self-Declaring Backup Ingest Specification

**Document Version**: 1.0.0  
**Target Audience**: KySecurity Suite Engineers, Business.app Ecosystem Developers, DevOps / Site Reliability Engineers  
**System Status**: Production-Ready / Integrated  

---

## 1. Executive Summary & Architecture Overview

The **Zero-Code Product Pairing & Self-Declaring Backup System** enables any KySecurity or Business.app software service (e.g., `kysignon`, `kypassword`, `kynotes`, `kybookmarks`, `kypost`, custom microservices) to securely connect with a centralized KyRecovery Server using an ephemeral 6-digit PIN code. 

Once paired, client applications push backups containing arbitrary database dumps, cryptographic keys, and environment specifications alongside a **declarative verification recipe**. KyRecovery ingests, encapsulates, encrypts with Shamir quorum thresholds, and executes automated ephemeral restore drills in isolated scratch sandboxes without requiring custom adapter code or server restarts.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as KyRecovery Administrator
    participant RecUI as KyRecovery Dashboard / CLI
    actor ServiceAdmin as Product Admin (KyNotes / KyPost)
    participant Client as Client Application Server
    participant RecServer as KyRecovery API Server

    rect rgb(22, 28, 38)
    note over Admin,RecServer: Phase 1: Zero-Trust Pairing Ceremony
    Admin->>RecUI: Click "+ Generate Pairing Code" (e.g. for "kynotes")
    RecUI->>RecServer: POST /api/pairing/generate { service_name: "kynotes" }
    RecServer-->>RecUI: 6-Digit PIN Code (e.g. "849201", TTL: 15 min)
    Admin-->>ServiceAdmin: Provides 6-digit PIN out-of-band
    ServiceAdmin->>Client: Inputs 6-digit PIN in product config
    Client->>RecServer: POST /api/pairing/claim { pairing_code: "849201", app_name: "KyNotes Primary" }
    RecServer->>RecServer: Validates PIN, marks claimed, generates API Bearer Token
    RecServer-->>Client: { api_token: "kyrec_live_...", pairing_id: "pair-..." }
    end

    rect rgb(18, 34, 30)
    note over Client,RecServer: Phase 2: Self-Declaring Backup Ingest & Verification
    Client->>Client: Bundles DB, Private Keys, Env Vars + Declarative Recipe
    Client->>RecServer: POST /api/backup/push (Bearer Token + JSON Payload)
    RecServer->>RecServer: Authenticates Token & Validates Schema
    RecServer->>RecServer: Packs into Encrypted .kycap Container (Shamir M-of-N)
    RecServer->>RecServer: Spawns Isolated 0700 Sandbox & Executes Declared Recipe
    RecServer->>RecServer: Replicates to Active Offsite Cloud Targets (S3/R2)
    RecServer->>RecServer: Records Hash-Chained Audit Ledger Event
    RecServer-->>Client: 200 OK { capsule_id, drill_summary: { passed: true, duration_ms: 42 } }
    end
```

---

## 2. API Protocol & Endpoints Specification

### 2.1. Pairing Code Generation (Admin / Dashboard)

- **Endpoint**: `POST /api/pairing/generate`
- **Authentication**: KyRecovery Admin Session (Cookie or Header)
- **Request Body**:
  ```json
  {
    "service_name": "kynotes",
    "ttl_minutes": 15
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "id": "pair-1787019014811345071",
    "service_name": "kynotes",
    "pairing_code": "849201",
    "status": "pending",
    "expires_at": "2026-08-18T02:25:14.811345071Z",
    "created_at": "2026-08-18T02:10:14.811345071Z"
  }
  ```

---

### 2.2. Pairing Claim & Token Exchange (Client Application)

- **Endpoint**: `POST /api/pairing/claim`
- **Authentication**: None (Protected by 6-digit single-use PIN and rate limiting)
- **Request Body**:
  ```json
  {
    "pairing_code": "849201",
    "app_name": "KyNotes Production Cluster US-East"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "id": "pair-1787019014811345071",
    "service_name": "kynotes",
    "app_name": "KyNotes Production Cluster US-East",
    "api_token": "kyrec_live_7a3d90e2f5b64c18a901ee45bc2990d1",
    "status": "paired",
    "paired_at": "2026-08-18T02:11:00Z"
  }
  ```
- **Error Codes**:
  - `400 Bad Request`: Invalid or expired pairing code.
  - `409 Conflict`: Pairing code already claimed.

---

### 2.3. Self-Declaring Backup Push (Client Application)

- **Endpoint**: `POST /api/backup/push` *(alias: `/api/v1/backup/push`)*
- **Authentication**: `Authorization: Bearer <api_token>`
- **Request Body**:
  ```json
  {
    "service_name": "kynotes",
    "app_version": "1.4.2",
    "threshold": 2,
    "total_shares": 3,
    "files": [
      {
        "path": "data/notes.db",
        "data_base64": "U1BMSVRlIGZvcm1hdCAzAA...",
        "mode": 384
      },
      {
        "path": "certs/jwt_signing.key",
        "data_base64": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ...",
        "mode": 384
      }
    ],
    "dependencies": {
      "ports": [8080],
      "env": ["KY_ISSUER", "DATABASE_URL"]
    },
    "verification_recipe": {
      "check_sqlite_integrity": true,
      "sqlite_paths": ["data/notes.db"],
      "test_signing_key_path": "certs/jwt_signing.key",
      "signing_algorithm": "rsa",
      "required_files": ["data/notes.db", "certs/jwt_signing.key"],
      "expected_env": ["KY_ISSUER", "DATABASE_URL"],
      "expected_ports": [8080]
    }
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "status": "ingested",
    "capsule_id": "cap-kynotes-1787019014",
    "service_name": "kynotes",
    "size_bytes": 1048576,
    "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "shares": [
      { "index": 1, "value_hex": "d8f3b2..." },
      { "index": 2, "value_hex": "4a9e10..." },
      { "index": 3, "value_hex": "1c77aa..." }
    ],
    "drill_summary": {
      "passed": true,
      "duration_ms": 42,
      "checks": [
        { "name": "Directory Unpack", "passed": true, "message": "Extracted 2 files (1.00 MB)" },
        { "name": "Required Files", "passed": true, "message": "All 2 required files verified" },
        { "name": "SQLite Integrity: data/notes.db", "passed": true, "message": "PRAGMA integrity_check passed ok" },
        { "name": "Signing Key: certs/jwt_signing.key", "passed": true, "message": "Parsed RSA private key (2048 bits), signing & verification cycle passed" },
        { "name": "Environment Variables", "passed": true, "message": "All 2 declared environment variables verified" },
        { "name": "Network Ports", "passed": true, "message": "All 1 declared network ports verified" }
      ]
    }
  }
  ```

---

## 3. Declarative Verification Recipe Schema

Client applications declare their verification contract directly in `verification_recipe`. The KyRecovery server executes these validation checks during sandbox restore drills:

| Field | Type | Description |
| :--- | :--- | :--- |
| `check_sqlite_integrity` | `boolean` | If true, executes `PRAGMA integrity_check` on all databases in `sqlite_paths`. |
| `sqlite_paths` | `string[]` | Relative file paths of SQLite database files within the archive. |
| `test_signing_key_path` | `string` | Relative path to RSA or ECDSA private key PEM file to test signing/verification. |
| `signing_algorithm` | `string` | `"rsa"` (RSA PKCS#1v15 / SHA-256) or `"ecdsa"` (ECDSA P-256 / SHA-256). |
| `required_files` | `string[]` | List of relative file paths that must exist and be non-empty after restoration. |
| `expected_env` | `string[]` | Environment variables required for application operation. |
| `expected_ports` | `integer[]` | TCP/UDP ports declared by the service. |

---

## 4. Client Integration Examples

### 4.1. Go Client Implementation

```go
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type BackupFile struct {
	Path       string `json:"path"`
	DataBase64 string `json:"data_base64"`
	Mode       int    `json:"mode"`
}

type PushPayload struct {
	ServiceName        string                 `json:"service_name"`
	AppVersion         string                 `json:"app_version"`
	Threshold          int                    `json:"threshold"`
	TotalShares        int                    `json:"total_shares"`
	Files              []BackupFile           `json:"files"`
	Dependencies       map[string]interface{} `json:"dependencies"`
	VerificationRecipe map[string]interface{} `json:"verification_recipe"`
}

func pushBackup(serverURL, apiToken string) error {
	dbBytes, _ := os.ReadFile("notes.db")
	keyBytes, _ := os.ReadFile("signing.key")

	payload := PushPayload{
		ServiceName: "kynotes",
		AppVersion:  "1.4.2",
		Threshold:   2,
		TotalShares: 3,
		Files: []BackupFile{
			{Path: "data/notes.db", DataBase64: base64.StdEncoding.EncodeToString(dbBytes), Mode: 0600},
			{Path: "certs/signing.key", DataBase64: base64.StdEncoding.EncodeToString(keyBytes), Mode: 0600},
		},
		Dependencies: map[string]interface{}{
			"ports": []int{8080},
			"env":   []string{"KY_ISSUER", "DATABASE_URL"},
		},
		VerificationRecipe: map[string]interface{}{
			"check_sqlite_integrity": true,
			"sqlite_paths":          []string{"data/notes.db"},
			"test_signing_key_path":  "certs/signing.key",
			"signing_algorithm":      "rsa",
			"required_files":         []string{"data/notes.db", "certs/signing.key"},
			"expected_env":           []string{"KY_ISSUER", "DATABASE_URL"},
			"expected_ports":         []int{8080},
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/api/backup/push", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backup failed with status: %d", resp.StatusCode)
	}
	fmt.Println("✓ Backup successfully ingested and verified by KyRecovery!")
	return nil
}
```

---

### 4.2. Python Client Implementation

```python
import base64
import requests

def push_backup(server_url: str, api_token: str):
    with open("notes.db", "rb") as f:
        db_b64 = base64.b64encode(f.read()).decode("utf-8")
    with open("signing.key", "rb") as f:
        key_b64 = base64.b64encode(f.read()).decode("utf-8")

    payload = {
        "service_name": "kynotes",
        "app_version": "1.4.2",
        "threshold": 2,
        "total_shares": 3,
        "files": [
            {"path": "data/notes.db", "data_base64": db_b64, "mode": 384},
            {"path": "certs/signing.key", "data_base64": key_b64, "mode": 384},
        ],
        "dependencies": {
            "ports": [8080],
            "env": ["KY_ISSUER", "DATABASE_URL"],
        },
        "verification_recipe": {
            "check_sqlite_integrity": True,
            "sqlite_paths": ["data/notes.db"],
            "test_signing_key_path": "certs/signing.key",
            "signing_algorithm": "rsa",
            "required_files": ["data/notes.db", "certs/signing.key"],
            "expected_env": ["KY_ISSUER", "DATABASE_URL"],
            "expected_ports": [8080],
        },
    }

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    res = requests.post(f"{server_url}/api/backup/push", json=payload, headers=headers)
    res.raise_for_status()
    print("✓ Backup ingested and verified:", res.json())
```

---

### 4.3. cURL CLI One-Liner

```bash
# 1. Claim pairing code
curl -s -X POST https://recovery.internal:8080/api/pairing/claim \
  -H "Content-Type: application/json" \
  -d '{"pairing_code":"849201","app_name":"KyNotes Node 1"}'

# 2. Push self-declared backup payload
curl -s -X POST https://recovery.internal:8080/api/backup/push \
  -H "Authorization: Bearer kyrec_live_7a3d90e2..." \
  -H "Content-Type: application/json" \
  -d @backup_payload.json
```

---

## 5. Security Invariants & Guarantees

1. **Content-Blind Cryptographic Encapsulation**: Ingested payloads are encrypted immediately with standard AES-256-GCM using an ephemeral 256-bit symmetric key split via Shamir's Secret Sharing ($M$-of-$N$).
2. **Ephemeral Sandbox Isolation**: Restore verification drills run in temporary scratch directories with strict POSIX `0700` permissions. Upon drill completion, the scratch directory is cryptographically scrubbed and wiped from disk.
3. **Single-Use Ephemeral PINs**: Pairing codes expire after 15 minutes (or configurable TTL) and are invalidated immediately upon first claim.
4. **Tamper-Evident Hash-Chained Audit Ledger**: Every pairing generation, claim, backup push, and verification drill event is cryptographically sealed into the SHA-256 hash chain with strict sequential monotonic IDs.
5. **Zero-Secret Logging**: In accordance with `LOGGING.md`, logs emit structured logfmt/JSON containing only capsule IDs, sequence numbers, and byte sizes—never API tokens, payload contents, or decryption keys.
