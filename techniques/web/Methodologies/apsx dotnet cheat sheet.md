# ASP.NET Web Application Testing Cheat Sheet

## Check for Exposed Configuration Files

Try accessing:

```
/web.config
```

- May expose:
  - Connection strings
  - Debug settings
  - Machine keys

---

## 2. ViewState Attacks

Look for hidden fields like:

```html
<input type="hidden" name="__VIEWSTATE" value="..." />
```

- If unsigned or weakly protected:
  - Can inject malicious ViewState
  - Exploit via `ysoserial.net`
- Supporting fields:
  - `__VIEWSTATEGENERATOR`
  - `__EVENTVALIDATION`

### 🛠 Tools:
- Burp Extension: ViewState Decoder
- `ysoserial.net`

---

## Trace Handler Exposure

Check:

```
/trace.axd
```

- May leak:
  - Request/response headers
  - Server variables
  - ASP.NET pipeline data

---

## ELMAH Logging Interface

Try:

```
/elmah.axd
```

- Exposes:
  - Stack traces
  - Source code references
  - Internal errors

---

## ASP.NET-Specific Endpoints

Look for:
- `.aspx` - Web pages
- `.ashx` - HTTP Handlers
- `.axd` - Diagnostics, scripts
- `.asmx` - Web Services
- `.svc` - WCF Services

Common paths:

```
/services/test.asmx
/api.svc
/resource.ashx
/trace.axd
```

---

## Machine Key Disclosure

Check `web.config` for:

```xml
<machineKey validationKey="..." decryptionKey="..." />
```

If known, allows:
- ViewState forgery
- FormsAuth ticket creation
- Decryption of app secrets

---

## Forms Authentication Cookie Abuse

Check for:
```
.ASPXAUTH
```

Test:
- Replay attacks
- Tampering (if unsigned)
- Forging (if machine key is known)

---

## HTTP Verb Tampering

Try:

```bash
curl -X HEAD https://target.com/login.aspx
curl -X TRACK https://target.com/
```

Older IIS servers may process unexpected HTTP methods.

---

## ASP.NET Sensitive File Extensions

Check for:

```
.aspx, .ashx, .asmx, .svc, .axd, .config
```

Use tools like `curl`, `dirsearch`, `ffuf`, or `nikto`.

---

## Tools

| Tool             | Purpose                          |
|------------------|----------------------------------|
| `ysoserial.net`  | ViewState payload generation     |
| `Burp Suite`     | Manual testing + ViewState decode|
| `Nikto`          | Path scanning and detection      |
| `nmap`           | IIS-specific NSE scripts         |
