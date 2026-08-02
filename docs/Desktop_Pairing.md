# Desktop Pairing Implementation Guide

## Overview

Desktop pairing allows users to initiate pairing with a desktop application. The feature generates a pairing code that can be used by desktop clients to authenticate and pair with the user's account.

**Quick Links:**
- 👤 **For Users:** Click "Pair Desktop App" button in Settings → Pairing page
- 👨‍💻 **For Desktop App Developers:** See [Complete API Reference](#complete-api-reference-for-desktop-apps) and [Minimal Working Example](#minimal-working-example-python)
- 🔐 **For Security:** See [Security Considerations](#security-considerations) and [Security Checklist](#desktop-app-security-checklist)
- 🧪 **For Testing:** See [Testing](#testing)

---

## Current Implementation Status

✅ **Phase 1 Completed:**
- Frontend UI with "Pair Desktop App" button
- Backend endpoint: `POST /api/notifications/desktop/pair`
- Pairing code generation (16-byte random = 128-bit entropy)
- Persistent storage of pairing codes in user state
- 5-minute TTL with automatic expiration
- Rate limiting: max 5 failed attempts per hour per user
- Code validation methods for backend consumers
- Attempt tracking for security audit trail
- Security-conscious logging (only code prefix exposed, sensitive data hidden)

## API Endpoint

### POST `/api/notifications/desktop/pair`

Initiates desktop pairing and returns a secure pairing code.

**Authentication:** Requires valid user session (uses `withAuth` middleware)

**Rate Limit:** Max 5 failed pairing attempts per hour per user

**Request Body:**
```json
{}
```

**Response (Success - 200 OK):**
```json
{
  "ok": true,
  "pairingCode": "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
  "ttlSeconds": 300,
  "rateLimit": 4,
  "serverBaseUrl": "https://example.com",
  "registerEndpoint": "https://example.com/api/notifications/desktop/register"
}
```

**Deep Link Format:**
```
kypost://desktop-pair?code=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6&srv=https://example.com
```

When the user clicks "Pair Desktop App":
1. Frontend calls this endpoint
2. Frontend constructs deep link with code + server URL
3. Frontend navigates to deep link (launches desktop app if installed)
4. Desktop app receives code + server endpoint
5. Desktop app calls `/api/notifications/desktop/register` to exchange code for token

**Response (Rate Limited - 429):**
```json
{
  "error": "rate limit exceeded: too many pairing attempts. Try again later."
}
```

**Format:** 32-character hex string (16 bytes = 128-bit entropy)
- Not human-typeable, delivered via API/QR code only
- Cryptographically secure random generation
- Single-use, 5-minute expiration
```

**Response (Error - 401):**
```json
{"error": "unauthorized"}
```

**Response (Error - 500):**
```
failed to generate pairing code
```

## Implementation Details

### Backend (server.go + state/store.go)

The `handleDesktopPair` handler:
1. Validates user authentication via session cookie
2. **Checks rate limit:** max 5 failed attempts per hour per user
3. Generates 16-byte cryptographically random code (128 bits entropy)
4. Returns code as 32-character uppercase hex string (no formatting)
5. Stores code in user's state store with 5-minute expiration
6. Records attempt for rate limiting and audit trail
7. Logs event with code prefix only (full code never in logs)
8. Returns code + TTL + remaining rate limit to frontend

**State Store Methods:**
- `SetDesktopPairingCode(code, ttl)` — Stores code with expiration
- `ValidateDesktopPairingCode(code) bool` — Checks if code is valid/not expired
- `ConsumeDesktopPairingCode(code)` — Validates and removes code (for registration)
- `CheckDesktopPairingRateLimit() (allowed, remaining, error)` — Checks rate limit
- `RecordDesktopPairingAttempt(code, success)` — Records attempt for rate limiting

**Persistence:**
- Codes stored in the user's `state.db` (`desktop_pairing_codes` table)
- Attempt history stored (last 100 attempts, 24-hour retention)
- Automatic cleanup of expired codes and old attempts on load/persist
- Survives server restart

**Rate Limiting:**
- **Limit:** 5 failed attempts per hour per user
- **Tracking:** Per-user in state file; survives server restart
- **Response:** 429 Too Many Requests when limit exceeded
- **Cleanup:** Attempts older than 24 hours automatically removed

**TTL Details:**
- **Default:** 5 minutes (300 seconds, configurable)
- **Storage:** RFC3339 formatted timestamp in user state
- **Cleanup:** Expired codes removed when state is loaded or persisted

**Security Implementation:**
- ✅ 128-bit cryptographic entropy (secure against brute force)
- ✅ Rate limiting (5 attempts/hour prevents exhaustive search)
- ✅ 5-minute TTL (time window for attack is minimal)
- ✅ Single-use codes (consumed on validation)
- ✅ Per-user state isolation (no cross-user attack surface)
- ✅ Code never fully logged (only 8-char prefix for correlation)
- ✅ Attempt tracking for security audit trail
- ✅ 429 response prevents client confusion (not 401/403)

### Frontend (NotificationsPage.tsx)

The `pairDesktopApp()` function:
1. Shows loading state ("Pairing...")
2. Calls `POST /api/notifications/desktop/pair`
3. Receives pairing code + server endpoint
4. **Constructs deep link:** `kypost://desktop-pair?code=...&srv=...`
5. **Attempts to launch** desktop app via deep link (`window.location.href = deepLink`)
6. **Fallback (2sec delay):** If app not installed, shows code for manual entry
7. Shows status message with next steps

**Helper Function:**
```typescript
function buildDesktopPairingLink(pairingCode: string, serverUrl?: string): string {
  const params = new URLSearchParams();
  params.set("code", pairingCode);
  if (serverUrl) {
    params.set("srv", serverUrl);
  }
  return `kypost://desktop-pair?${params.toString()}`;
}
```

**Flow Diagram:**
```
User clicks "Pair Desktop App"
         ↓
Frontend calls /api/notifications/desktop/pair
         ↓
Backend returns code + server endpoint
         ↓
Frontend constructs: kypost://desktop-pair?code=...&srv=...
         ↓
Frontend navigates to deep link
         ├─→ Desktop app installed? → App launches, receives code
         └─→ App not installed? → Status shows: "Share this code: ..."
         ↓
Desktop app calls /api/notifications/desktop/register (Phase 2)
         ↓
Desktop app receives session token
         ↓
Pairing complete ✓
```

**UI Integration:**
- Button location: "Mobile App Pairing" section (replacing "Revoke Paired Devices")
- "Revoke Paired Devices" moved to footer, left of "Unsubscribe This Device"
- Navigation label changed from "Notifications" to "Pairing"
- Page title changed to "Notifications and Pairing"
- Status message shows countdown timer during pairing window
- Fallback message if desktop app not installed

## Complete API Reference for Desktop Apps

### Step 1: Initiate Pairing (Browser Calls This)

#### `POST /api/notifications/desktop/pair`

**Called by:** Web browser when user clicks "Pair Desktop App" button  
**Authentication:** Session cookie (user must be logged in)  
**Rate Limit:** 5 failed attempts per hour per user

**Request:**
```bash
curl -X POST https://example.com/api/notifications/desktop/pair \
  -H "Content-Type: application/json" \
  -b "session=..." \
  -d '{}'
```

**Response (200 OK):**
```json
{
  "ok": true,
  "pairingCode": "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
  "ttlSeconds": 300,
  "rateLimit": 4,
  "serverBaseUrl": "https://example.com",
  "registerEndpoint": "https://example.com/api/notifications/desktop/register"
}
```

**Response (429 Too Many Requests - Rate Limited):**
```json
{
  "error": "rate limit exceeded: too many pairing attempts. Try again later."
}
```

**Response (401 Unauthorized):**
```json
{"error": "unauthorized"}
```

---

### Step 2: Desktop App Receives Deep Link

Browser creates and navigates to:
```
kypost://desktop-pair?code=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6&srv=https://example.com
```

**Desktop App must:**
1. Register `kypost://` protocol handler
2. Parse query parameters: `code` and `srv`
3. Display pairing prompt to user (optional)
4. Proceed to Step 3

---

### Step 3: Exchange Code for Token (Desktop App Calls This)

#### `POST /api/notifications/desktop/register`

**Called by:** Desktop application  
**Authentication:** Pairing code (no session required)  
**Note:** Code is valid for 5 minutes, single-use only

**Request:**
```bash
curl -X POST https://example.com/api/notifications/desktop/register \
  -H "Content-Type: application/json" \
  -d '{
    "pairingCode": "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
    "appName": "KyPost Desktop",
    "appVersion": "1.0.0",
    "platformInfo": "macOS/arm64"
  }'
```

**Request Fields:**
- `pairingCode` (string, required): The 32-character code from deep link
- `appName` (string, optional): Display name of desktop app
- `appVersion` (string, optional): Version of desktop app
- `platformInfo` (string, optional): Platform/OS/architecture info

**Response (200 OK - Pairing Successful):**
```json
{
  "ok": true,
  "sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "expiresIn": 86400,
  "userId": "user123",
  "userEmail": "user@example.com"
}
```

**Response (401 Unauthorized - Invalid/Expired Code):**
```json
{"error": "invalid or expired pairing code"}
```

**Response (409 Conflict - Code Already Used):**
```json
{"error": "pairing code already consumed"}
```

**Response (400 Bad Request - Missing/Invalid Fields):**
```json
{"error": "pairingCode is required"}
```

---

### Step 4: Use Session Token for API Requests

Desktop app now uses the `sessionToken` as a Bearer token for all subsequent requests:

```bash
curl -X GET https://example.com/api/auth/me \
  -H "Authorization: Bearer eyJhbGci..."
```

All authenticated endpoints require this token in the `Authorization` header:
```
Authorization: Bearer <sessionToken>
```

---

## Phase 2: Desktop App Registration (Ready to Implement)

### Endpoint: `POST /api/notifications/desktop/register`

Desktop app calls this endpoint to exchange pairing code for a session token.

**Request Body:**
```json
{
  "pairingCode": "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
  "appName": "KyPost Desktop",
  "appVersion": "1.0.0",
  "platformInfo": "Linux/x86_64"
}
```

**Response (Success - 200 OK):**
```json
{
  "ok": true,
  "sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 86400,
  "userId": "user123"
}
```

**Response (Invalid Code - 401):**
```json
{"error": "invalid or expired pairing code"}
```

**Response (Code Already Used - 409):**
```json
{"error": "pairing code already consumed"}
```

**Implementation Requirements:**
1. ❌ Validate pairing code exists and not expired
2. ❌ Call `store.ConsumeDesktopPairingCode()` to validate + remove code
3. ❌ Record successful pairing in attempt history
4. ❌ Create session token (JWT or similar)
5. ❌ Store paired desktop session metadata:
   - App name / version
   - Platform info
   - IP address / timestamp
   - Session token hash
6. ❌ Return token with expiration
7. ❌ Log successful pairing

---

## Implementation Roadmap

### ✅ Phase 1: Secure Code Generation (COMPLETE)
- [x] 16-byte (128-bit) cryptographic random code
- [x] Persistent storage with 5-minute TTL
- [x] Rate limiting (5 failed attempts/hour per user)
- [x] Attempt tracking for audit trail
- [x] Security-conscious logging
- [x] Deep link construction + launch
- [x] Server endpoint + code delivery to desktop app

### Phase 2: Desktop App Registration Endpoint (READY)
- [ ] Implement `POST /api/notifications/desktop/register`
- [ ] Validate and consume pairing code
- [ ] Create session token
- [ ] Store paired desktop session
- [ ] Return token to desktop app

### Phase 3: Desktop Session Management
- [ ] Add `GET /api/notifications/desktop/sessions` — List paired desktop apps
- [ ] Add `DELETE /api/notifications/desktop/sessions/{id}` — Revoke specific session
- [ ] Add `POST /api/notifications/desktop/unpair` — Revoke all desktop pairings
- [ ] Session metadata: app name, version, OS, last activity, IP address
- [ ] Activity dashboard for user to review active sessions

### Phase 4: Advanced Features
- [ ] QR code generation containing full pairing code
- [ ] Desktop app push notifications via established session
- [ ] Anomaly detection: unusual pairing location/time
- [ ] Paired device recovery flow (device lost, factory reset, etc.)

## Security Considerations

**Implemented (Defense in Depth):**
- ✅ **Strong entropy:** 16 bytes = 128 bits (2^128 combinations)
- ✅ **Rate limiting:** 5 failed attempts per hour per user
- ✅ **Short TTL:** 5-minute window for pairing window
- ✅ **Single-use:** Codes consumed and removed after validation
- ✅ **Session requirement:** Only authenticated users can initiate
- ✅ **State isolation:** Per-user encrypted state directory
- ✅ **No logging:** Full code never in logs (only 8-char prefix)
- ✅ **Attempt tracking:** All pairing attempts recorded for audit
- ✅ **Automatic cleanup:** Expired codes and old attempts removed

**Threat Model:**

| Threat | Mitigation | Residual Risk |
|--------|-----------|----------------|
| **Brute force** | 128 bits + 5 attempts/hour limit = ~44 years to exhaust | Low |
| **Code interception** | 5-min TTL, delivered via secure API/QR only | Low |
| **Session hijacking** | Uses standard authenticated session | Low (same as login) |
| **Log exposure** | Code prefix only in logs, full code never logged | Low |
| **Replay attack** | Single-use codes, consumed after validation | Low |
| **Rate limit bypass** | Per-user state-based tracking (survives restart) | Low |

**Recommended for Production:**
- ⚠️ Enforce HTTPS for all API traffic (transport security)
- ⚠️ Consider TOTP requirement for high-security operations
- ⚠️ Implement dashboard showing active paired sessions
- ⚠️ Add email/SMS notification when new device paired
- ⚠️ Monitor for unusual pairing patterns in logs
- ⚠️ Consider geographic/network anomaly detection

**Not Required (Overkill Given Controls):**
- ❌ Increasing entropy beyond 128 bits (already unbreakable)
- ❌ Reducing TTL below 5 minutes (limits legitimate use)
- ❌ More than 5 attempts/hour limit (acceptable UX + security)

## Desktop App Implementation Guide

### Quick Start: Pairing Flow

```
1. User opens website → clicks "Pair Desktop App"
   ↓
2. Browser receives pairing code + server URL
   ↓
3. Browser launches deep link: kypost://desktop-pair?code=...&srv=...
   ↓
4. Desktop app wakes up, parses parameters
   ↓
5. Desktop app sends code to: POST /api/notifications/desktop/register
   ↓
6. Server returns sessionToken
   ↓
7. Desktop app stores token securely (keychain/credential store)
   ↓
8. Desktop app uses token for all future API requests
   ↓
9. Pairing complete ✓
```

### Protocol Handler Registration

**macOS (Info.plist):**
```xml
<dict>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key>
      <string>KyPost Pairing</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>kypost</string>
      </array>
    </dict>
  </array>
</dict>
```

**Windows (Registry):**
```
HKEY_CLASSES_ROOT
  kypost
    (Default) = "URL:KyPost"
    URL Protocol = ""
    shell
      open
        command
          (Default) = "C:\Program Files\KyPost\app.exe" "%1"
```

**Linux (desktop file):**
```ini
[Desktop Entry]
Exec=kypost-app %U
MimeType=x-scheme-handler/kypost
```

### Pseudocode: Desktop App Pairing Handler

```python
def handle_deep_link(url):
    """Called when user clicks pairing link or app opens with link"""
    
    # Parse deep link: kypost://desktop-pair?code=...&srv=...
    params = parse_url_params(url)
    code = params.get('code')
    server_url = params.get('srv')
    
    if not code or not server_url:
        show_error("Invalid pairing link")
        return
    
    # Exchange code for token
    try:
        response = requests.post(
            f"{server_url}/api/notifications/desktop/register",
            json={
                "pairingCode": code,
                "appName": "KyPost Desktop",
                "appVersion": "1.0.0",
                "platformInfo": f"{sys.platform}/{platform.machine()}"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            session_token = data['sessionToken']
            expires_in = data['expiresIn']
            user_email = data.get('userEmail')
            
            # Store token securely
            store_token_securely(session_token, expires_in)
            show_success(f"Paired as {user_email}")
            
        elif response.status_code == 429:
            show_error("Rate limited. Wait 1 hour and try again.")
        elif response.status_code == 401:
            error = response.json().get('error')
            show_error(f"Pairing failed: {error}")
        else:
            show_error("Unexpected server error")
            
    except requests.exceptions.Timeout:
        show_error("Server unreachable")
    except Exception as e:
        show_error(f"Pairing error: {e}")

def make_api_request(endpoint, method="GET", data=None):
    """Make authenticated API request using stored token"""
    
    token = get_stored_token()
    if not token:
        show_error("Not paired. Run pairing flow first.")
        return None
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        if method == "GET":
            response = requests.get(endpoint, headers=headers)
        elif method == "POST":
            response = requests.post(endpoint, json=data, headers=headers)
        # ... handle other methods
        
        if response.status_code == 401:
            # Token expired or invalid
            clear_stored_token()
            show_error("Session expired. Please pair again.")
            return None
        
        return response.json()
        
    except Exception as e:
        show_error(f"API request failed: {e}")
        return None
```

### Token Storage Best Practices

**Never log or expose the full token.**

**Store securely using platform APIs:**

**Python:**
```python
import keyring

# Store
keyring.set_password("kypost", "session_token", token)

# Retrieve
token = keyring.get_password("kypost", "session_token")

# Delete
keyring.delete_password("kypost", "session_token")
```

**Electron (TypeScript):**
```typescript
import { safeStorage } from 'electron';

// Store (encrypted in memory)
const encrypted = safeStorage.encryptString(token);
store.set('token', encrypted);

// Retrieve (decrypted on access)
const decrypted = safeStorage.decryptString(
  Buffer.from(store.get('token'), 'latin1')
);
```

**Native (Swift):**
```swift
import Security

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "kypost",
    kSecValueData as String: token.data(using: .utf8)!
]

SecItemAdd(query as CFDictionary, nil)
```

---

## Related Files

- Frontend: [frontend/src/pages/NotificationsPage.tsx](../frontend/src/pages/NotificationsPage.tsx)
- Backend: [backend/internal/api/server.go](../backend/internal/api/server.go) - `handleDesktopPair` (line 1328+)
- State store: [backend/internal/state/store.go](../backend/internal/state/store.go) - Desktop pairing methods
- Mobile pairing reference: [backend/internal/api/server.go](../backend/internal/api/server.go) - `handleNotificationPairing` (line 1020)
- App navigation: [frontend/src/App.tsx](../frontend/src/App.tsx) - Line 26 (nav label)

## Desktop App Security Checklist

Before shipping a desktop app with pairing support:

- ✅ Store session token only in secure credential store (keychain/credential vault)
- ✅ Never log, print, or expose the full session token
- ✅ Use HTTPS only (never HTTP)
- ✅ Validate server certificate (no self-signed in production)
- ✅ Handle token expiration gracefully (check `expiresIn` response field)
- ✅ Implement token refresh logic (future: `/api/notifications/desktop/refresh`)
- ✅ Clear token on logout/unpair
- ✅ Add "Forget This Computer" UI to clear pairing
- ✅ Handle deep link even if app is already running (re-pair scenario)
- ✅ Show user which account is paired + paired timestamp
- ✅ Validate `pairingCode` format before sending (32 hex chars)
- ✅ Implement exponential backoff for failed registrations
- ✅ Never retry token exchange more than 3 times (hits rate limit)

---

## Common Issues & Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Deep link not launching app | Protocol handler not registered | Register `kypost://` handler in OS |
| "Invalid or expired code" | Waited >5 minutes after getting code | Pairing codes expire after 5 min. Get a new one |
| "Code already consumed" | Tried to use same code twice | Each code is single-use. Get a new one |
| Rate limit after 5 attempts | Exceeded 5 failed attempts/hour | Wait 1 hour before retrying |
| Token stops working | Session expired | Implement token refresh or re-pair |
| Can't connect to server | Server URL incorrect | Verify `srv` param from deep link |
| 401 on API calls | Token not in Authorization header | Use: `Authorization: Bearer <token>` |

---

## Minimal Working Example (Python)

Here's a complete minimal desktop app that handles pairing:

```python
#!/usr/bin/env python3
import sys
import json
import requests
from urllib.parse import urlparse, parse_qs
import keyring

class LlamaLabelsDesktopApp:
    def __init__(self):
        self.server_url = None
        self.session_token = None
    
    def handle_pairing_link(self, deep_link):
        """Called when app launches with pairing link"""
        # Parse: kypost://desktop-pair?code=ABC123&srv=https://...
        parsed = urlparse(deep_link)
        params = parse_qs(parsed.query)
        
        code = params.get('code', [None])[0]
        server = params.get('srv', [None])[0]
        
        if not code or not server:
            print("❌ Invalid pairing link")
            return False
        
        return self.register_device(code, server)
    
    def register_device(self, code, server_url):
        """Exchange pairing code for session token"""
        self.server_url = server_url
        
        try:
            response = requests.post(
                f"{server_url}/api/notifications/desktop/register",
                json={
                    "pairingCode": code,
                    "appName": "KyPost Desktop (Python Demo)",
                    "appVersion": "0.1.0",
                    "platformInfo": f"{sys.platform}/python"
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.session_token = data['sessionToken']
                
                # Store token in system keyring
                keyring.set_password(
                    "kypost",
                    "session_token",
                    self.session_token
                )
                
                print(f"✅ Pairing successful!")
                print(f"   Paired as: {data.get('userEmail')}")
                print(f"   Token expires in: {data['expiresIn']}s")
                return True
            
            elif response.status_code == 401:
                print(f"❌ Pairing failed: {response.json().get('error')}")
                return False
            
            elif response.status_code == 429:
                print(f"❌ Rate limited: {response.json().get('error')}")
                return False
            
            else:
                print(f"❌ Unexpected response: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def load_stored_token(self):
        """Load token from secure storage"""
        try:
            token = keyring.get_password("kypost", "session_token")
            if token:
                self.session_token = token
                return True
        except Exception as e:
            print(f"Failed to load token: {e}")
        
        return False
    
    def make_request(self, endpoint, method="GET", data=None):
        """Make authenticated API request"""
        if not self.session_token:
            print("❌ Not paired. Run pairing first.")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.session_token}",
            "Content-Type": "application/json"
        }
        
        url = f"{self.server_url}{endpoint}"
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=data, headers=headers, timeout=10)
            else:
                print(f"Unsupported method: {method}")
                return None
            
            if response.status_code == 401:
                print("❌ Session expired. Please re-pair.")
                keyring.delete_password("kypost", "session_token")
                self.session_token = None
                return None
            
            elif response.status_code == 200:
                return response.json()
            
            else:
                print(f"❌ API error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Request failed: {e}")
            return None

# Usage example
if __name__ == "__main__":
    app = LlamaLabelsDesktopApp()
    
    # If app receives a deep link (e.g., from URL scheme handler)
    if len(sys.argv) > 1:
        deep_link = sys.argv[1]
        app.handle_pairing_link(deep_link)
    
    # Otherwise, try to load stored token
    elif app.load_stored_token():
        print("✅ Using stored pairing")
        
        # Example: Get current user
        user = app.make_request("/api/auth/me")
        if user:
            print(f"Logged in as: {user.get('email')}")
    
    else:
        print("⚠️  Not paired. Visit the website and click 'Pair Desktop App'")
```

---

## Testing

**Manual test - Deep link launch (with desktop app):**
1. Install desktop app with `kypost://` deep link handler
2. Navigate to "Pairing" page in settings
3. Click "Pair Desktop App" button
4. ✅ Desktop app launches automatically
5. Desktop app receives code + server URL in deep link
6. Desktop app calls `/api/notifications/desktop/register` (Phase 2)
7. Pairing complete ✓

**Manual test - Fallback (without desktop app):**
1. Ensure no desktop app installed
2. Click "Pair Desktop App" button
3. Status message shows: "Launching desktop app with pairing code..."
4. After 2 seconds, if app not detected: "Desktop app not installed. Pairing code: A1B2C3D4..."
5. User can manually share code with desktop app
6. Desktop app exchanges code via `/api/notifications/desktop/register`

**Deep link format test:**
1. Manually construct deep link: `kypost://desktop-pair?code=ABC123...&srv=https://...`
2. Open in browser (or use `open` command)
3. Verify desktop app launches with correct parameters

**Rate limit test:**
1. Click "Pair Desktop App" 6 times rapidly
2. On 6th attempt, verify 429 response: `rate limit exceeded: too many pairing attempts`
3. Wait 1 hour, verify button works again (rate limit resets)

**Code expiration test:**
1. Capture a pairing code
2. Wait 5+ minutes
3. Try to use code with `/api/notifications/desktop/register` (Phase 2)
4. Verify 401: `invalid or expired pairing code`

**Error test:**
1. Click button without valid session
2. Verify 401 error in frontend
3. Check frontend displays error message

**Browser console (DevTools):**
```javascript
// Check what deep link is being used
// Open Network tab, click "Pair Desktop App"
// Look for navigation to: kypost://desktop-pair?code=...&srv=...
```
