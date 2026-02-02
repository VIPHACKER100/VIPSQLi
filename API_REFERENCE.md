# VIP SQLi Scanner v3.0 - API Reference

Complete API documentation for all endpoints.

## Base URL

```
http://localhost:5000
```

## Authentication

### JWT Token Authentication

Include the JWT token in the `Authorization` header:

```
Authorization: Bearer <token>
```

### API Key Authentication

Include the API key in the `X-API-Key` header:

```
X-API-Key: <api_key>
```

---

## Authentication Endpoints

### Register User

Create a new user account.

**Endpoint:** `POST /api/auth/register`

**Rate Limit:** 5 per hour

**Request Body:**
```json
{
  "username": "string (required)",
  "email": "string (required)",
  "password": "string (required)"
}
```

**Response:** `201 Created`
```json
{
  "message": "User created successfully",
  "user_id": 1,
  "api_key": "uuid-string"
}
```

**Errors:**
- `400` - Missing required fields
- `409` - Username or email already exists
- `500` - Registration failed

---

### Login

Authenticate and receive JWT token.

**Endpoint:** `POST /api/auth/login`

**Rate Limit:** 10 per minute

**Request Body:**
```json
{
  "username": "string (required)",
  "password": "string (required)"
}
```

**Response:** `200 OK`
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

**Errors:**
- `400` - Missing credentials
- `401` - Invalid credentials

---

### Refresh Token

Refresh an expired JWT token.

**Endpoint:** `POST /api/auth/refresh`

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "token": "new-jwt-token"
}
```

---

### Regenerate API Key

Generate a new API key for the authenticated user.

**Endpoint:** `POST /api/auth/api-key`

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "api_key": "new-uuid-string"
}
```

---

## Scan Management Endpoints

### List Scans

Get all scans for the authenticated user.

**Endpoint:** `GET /api/scans`

**Authentication:** Required

**Query Parameters:**
- `page` (integer, default: 1) - Page number
- `per_page` (integer, default: 20) - Results per page
- `status` (string, optional) - Filter by status: idle, running, paused, completed, stopped, error

**Response:** `200 OK`
```json
{
  "scans": [
    {
      "id": 1,
      "scan_id": "uuid-string",
      "name": "My Scan",
      "description": "Test scan",
      "status": "completed",
      "created_at": "2026-02-03T10:00:00",
      "started_at": "2026-02-03T10:01:00",
      "completed_at": "2026-02-03T10:05:00",
      "total_urls": 100,
      "scanned_urls": 100,
      "vulnerable_count": 5,
      "safe_count": 90,
      "error_count": 5,
      "suspicious_count": 0,
      "duration": 240.5,
      "config": {
        "ml_enabled": true,
        "threads": 25
      }
    }
  ],
  "total": 50,
  "pages": 3,
  "current_page": 1
}
```

---

### Get Scan Details

Get detailed information about a specific scan including all results.

**Endpoint:** `GET /api/scans/{scan_id}`

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "id": 1,
  "scan_id": "uuid-string",
  "name": "My Scan",
  "status": "completed",
  "total_urls": 100,
  "vulnerable_count": 5,
  "results": [
    {
      "id": 1,
      "url": "http://example.com/page?id=1",
      "verdict": "VULNERABLE",
      "risk_level": "high",
      "details": "SQL injection vulnerability detected",
      "payload_used": "1' OR '1'='1",
      "response_code": 200,
      "response_time": 0.523,
      "ml_confidence": 0.95,
      "ml_prediction": "vulnerable",
      "scanned_at": "2026-02-03T10:01:30",
      "verified": false,
      "false_positive": false
    }
  ]
}
```

**Errors:**
- `404` - Scan not found

---

### Delete Scan

Delete a scan and all its results.

**Endpoint:** `DELETE /api/scans/{scan_id}`

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "message": "Scan deleted successfully"
}
```

**Errors:**
- `404` - Scan not found

---

### Start Scan

Start a new security scan.

**Endpoint:** `POST /api/start`

**Rate Limit:** 10 per hour

**Authentication:** Optional (results saved to account if authenticated)

**Request Body:**
```json
{
  "urls": [
    "http://example.com/page?id=1",
    "http://example.com/search?q=test"
  ],
  "name": "My Scan (optional)",
  "description": "Scan description (optional)",
  "ml_enabled": true,
  "time_based": false,
  "plugins_enabled": true,
  "threads": 25,
  "profile": "balanced"
}
```

**Response:** `200 OK`
```json
{
  "message": "Scan started",
  "scan_id": "uuid-string",
  "total_urls": 2
}
```

**Errors:**
- `400` - Scan already running or no URLs provided
- `400` - Maximum 10,000 URLs per scan

---

### Pause Scan

Pause the currently running scan.

**Endpoint:** `POST /api/pause`

**Response:** `200 OK`
```json
{
  "message": "Scan paused"
}
```

**Errors:**
- `400` - No scan running

---

### Resume Scan

Resume a paused scan.

**Endpoint:** `POST /api/resume`

**Response:** `200 OK`
```json
{
  "message": "Scan resumed"
}
```

**Errors:**
- `400` - No paused scan

---

### Stop Scan

Stop the currently running scan.

**Endpoint:** `POST /api/stop`

**Response:** `200 OK`
```json
{
  "message": "Scan stopped"
}
```

**Errors:**
- `400` - No scan running

---

### Get Scan Status

Get real-time status of current scan (public endpoint).

**Endpoint:** `GET /api/status`

**Response:** `200 OK`
```json
{
  "running": true,
  "paused": false,
  "scan_id": "uuid-string",
  "progress": 50,
  "total": 100,
  "vulnerable": 5,
  "safe": 40,
  "errors": 5,
  "suspicious": 0,
  "current_url": "http://example.com/page?id=50",
  "elapsed_seconds": 123.45,
  "config": {
    "ml_enabled": true,
    "threads": 25
  }
}
```

---

## Export Endpoints

### Export Results

Export scan results in various formats.

**Endpoint:** `POST /api/export`

**Rate Limit:** 20 per hour

**Authentication:** Optional

**Request Body:**
```json
{
  "scan_id": "uuid-string (required)",
  "format": "json|csv|html|xml|markdown|pdf",
  "options": {
    "include_safe": false,
    "include_details": true,
    "include_payloads": true,
    "include_timestamps": true
  }
}
```

**Supported Formats:**
- `json` - JSON format with full data
- `csv` - Comma-separated values
- `html` - Beautiful HTML report with Bootstrap
- `xml` - XML format
- `markdown` - Markdown document
- `pdf` - PDF report (requires reportlab)

**Response:**
- File download with appropriate MIME type
- Filename: `scan_{scan_id}_{timestamp}.{ext}`

**Errors:**
- `400` - No results to export or invalid format
- `404` - Scan not found
- `501` - PDF export requires reportlab library

---

## Settings Endpoints

### Get Settings

Get application settings (public endpoint).

**Endpoint:** `GET /api/settings`

**Response:** `200 OK`
```json
{
  "max_concurrent": 100,
  "timeout": 20,
  "waf_detection": true,
  "error_based": true,
  "boolean_based": false,
  "notifications_enabled": true
}
```

---

### Update Settings

Update application settings (admin only).

**Endpoint:** `POST /api/settings`

**Authentication:** Required (admin role)

**Request Body:**
```json
{
  "max_concurrent": 150,
  "timeout": 30,
  "waf_detection": true,
  "notifications_enabled": true
}
```

**Response:** `200 OK`
```json
{
  "message": "Settings saved successfully"
}
```

**Errors:**
- `403` - Admin privileges required

---

## Analytics Endpoints

### Dashboard Analytics

Get dashboard analytics for the authenticated user.

**Endpoint:** `GET /api/analytics/dashboard`

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "total_scans": 150,
  "total_urls_scanned": 15000,
  "total_vulnerabilities": 75,
  "risk_distribution": {
    "critical": 5,
    "high": 15,
    "medium": 30,
    "low": 25
  },
  "scan_history": [
    {
      "date": "2026-02-03",
      "scans": 5,
      "vulnerabilities": 3
    }
  ],
  "recent_scans_count": 10
}
```

---

## File Upload Endpoints

### Upload URL List

Upload a file containing URLs to scan.

**Endpoint:** `POST /api/upload`

**Rate Limit:** 20 per hour

**Request:** `multipart/form-data`
- Field name: `file`
- Supported formats: `.txt`, `.csv`, `.json`
- Max size: 100MB

**Response:** `200 OK`
```json
{
  "message": "File processed successfully",
  "valid_urls": [
    "http://example.com/page?id=1",
    "http://example.com/search?q=test"
  ],
  "invalid_urls": [
    "not-a-url",
    "ftp://invalid.com"
  ],
  "total_valid": 2,
  "total_invalid": 2
}
```

**File Formats:**

**TXT:**
```
http://example.com/page?id=1
http://example.com/search?q=test
# Comments start with #
```

**CSV:**
```
url,priority
http://example.com/page?id=1,high
http://example.com/search?q=test,medium
```

**JSON:**
```json
{
  "urls": [
    "http://example.com/page?id=1",
    "http://example.com/search?q=test"
  ]
}
```

**Errors:**
- `400` - No file provided or invalid file type

---

## Utility Endpoints

### Health Check

Check application health status.

**Endpoint:** `GET /api/health`

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "version": "3.0",
  "database": "connected",
  "timestamp": "2026-02-03T10:00:00"
}
```

**Response:** `503 Service Unavailable` (if unhealthy)
```json
{
  "status": "unhealthy",
  "error": "Database connection failed"
}
```

---

## WebSocket Events

### Connection

Connect to WebSocket server for real-time updates.

**URL:** `ws://localhost:5000`

**Client Events (emit):**

#### join_scan
```javascript
socket.emit('join_scan', {
  scan_id: 'uuid-string'
});
```

#### leave_scan
```javascript
socket.emit('leave_scan', {
  scan_id: 'uuid-string'
});
```

#### request_status
```javascript
socket.emit('request_status');
```

**Server Events (on):**

#### connected
```javascript
socket.on('connected', (data) => {
  // data: { message, version, timestamp }
});
```

#### scan_update
```javascript
socket.on('scan_update', (data) => {
  /*
  data: {
    progress: 50,
    total: 100,
    current: 'http://example.com',
    vulnerable: 5,
    safe: 40,
    errors: 5,
    latest_result: { ... }
  }
  */
});
```

#### scan_complete
```javascript
socket.on('scan_complete', (data) => {
  /*
  data: {
    scan_id: 'uuid',
    total: 100,
    vulnerable: 5,
    safe: 90,
    errors: 5,
    elapsed: 240.5
  }
  */
});
```

#### scan_error
```javascript
socket.on('scan_error', (data) => {
  // data: { message: 'Error description' }
});
```

#### status_update
```javascript
socket.on('status_update', (data) => {
  // Same as GET /api/status response
});
```

---

## Error Codes

### Standard HTTP Status Codes

- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required or failed
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `501 Not Implemented` - Feature not available
- `503 Service Unavailable` - Service temporarily unavailable

### Error Response Format

```json
{
  "error": "Error type",
  "message": "Detailed error message"
}
```

---

## Rate Limiting

Default rate limits:
- **Register:** 5 per hour
- **Login:** 10 per minute
- **Start Scan:** 10 per hour
- **Export:** 20 per hour
- **Upload:** 20 per hour
- **Default:** 100 per hour

**Rate Limit Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1612345678
```

**Rate Limit Error:**
```json
{
  "error": "Rate limit exceeded",
  "message": "100 per 1 hour"
}
```

---

## Data Models

### User
```typescript
{
  id: number,
  username: string,
  email: string,
  role: 'user' | 'admin',
  created_at: datetime,
  is_active: boolean
}
```

### Scan
```typescript
{
  id: number,
  scan_id: string (UUID),
  name: string,
  description: string,
  status: 'idle' | 'running' | 'paused' | 'completed' | 'stopped' | 'error',
  created_at: datetime,
  started_at: datetime,
  completed_at: datetime,
  total_urls: number,
  scanned_urls: number,
  vulnerable_count: number,
  safe_count: number,
  error_count: number,
  suspicious_count: number,
  duration: number,
  config: object
}
```

### ScanResult
```typescript
{
  id: number,
  url: string,
  verdict: 'SAFE' | 'VULNERABLE' | 'ERROR' | 'SUSPICIOUS',
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info',
  details: string,
  payload_used: string,
  response_code: number,
  response_time: number,
  ml_confidence: number (0-1),
  ml_prediction: string,
  scanned_at: datetime,
  verified: boolean,
  false_positive: boolean,
  metadata: object,
  errors: array
}
```

---

## Best Practices

### Authentication
1. Store JWT tokens securely (httpOnly cookies recommended)
2. Refresh tokens before expiration
3. Use API keys for automation/CI/CD
4. Never expose API keys in client-side code

### Scanning
1. Batch URLs in reasonable sizes (100-1000 per scan)
2. Use appropriate thread counts (25-50 for most cases)
3. Enable ML for better accuracy
4. Monitor scan progress via WebSocket

### Performance
1. Use pagination for large result sets
2. Filter results when exporting (exclude safe URLs)
3. Cache frequently accessed data
4. Use Redis for production environments

### Security
1. Always validate input URLs
2. Respect rate limits
3. Use HTTPS in production
4. Keep dependencies updated
5. Change default admin password immediately

---

## Examples

See `QUICKSTART.md` for comprehensive client examples in:
- Python
- JavaScript/Node.js
- cURL

---

## Support

- **Issues:** GitHub Issues
- **Docs:** Full documentation in `/docs`
- **Email:** support@example.com

---

**API Version:** 3.0  
**Last Updated:** February 2026
