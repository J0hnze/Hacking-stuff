### OWASP Top 10 Checklist

#### 1. Broken Access Control

#### 2. Cryptographic Failures

#### 3. Injection

#### 4. Insecure Design

#### 5. Security Misconfiguration

#### 6. Vulnerable and Outdated Components

#### 7. Identification and Authentication Failures

#### 8. Software and Data Integrity Failures

#### 9. Security Logging and Monitoring Failures

#### 10. Server-Side Request Forgery (SSRF)

---

### Additional Checks

---

### Things Done Well

---

### Example Scripts & Commands

#### Version Enumeration

- **Nmap:**
    
    ```
    nmap -sV -sC -p 1-65535 <target-ip>
    ```
    
- **Curl (HTTP headers):**
    
    ```
    curl -I http://<target-url>
    ```
    
- **Nikto (web vulnerability scanner):**
    
```bash
nikto -h http://<target-url>
```
    
## Dirsearch 

example syntax

```bash
dirsearch -l targets.txt -e .aspx, .ashx, .asmx, .svc, .axd, .config -x 403,404  -o ./dirsearch-results.md
```



---

### Findings and Recommendations

- **Critical:**
    
- **High:**
    
- **Medium:**
    
- **Low:**
    

---

### Notes & Observations