## Nessus-ScanToggle.ps1 – Build Review Helper

This script is used during **Windows build reviews** to temporarily relax settings so a Nessus (or other) authenticated scan can run cleanly, then roll them back afterwards.

---

### Command-line options

- `-m`, `-Mode` (**required**)  
  - `Enable` – put the host into “scan ready” mode  
  - `Disable` – revert the changes after the scan

- `-s`, `-ScannerIPs` (optional)  
  - Comma-separated list of scanner IPs  
  - When used with `Enable`, creates inbound allow rules **only** for these IPs

- `-v`, `-Verbose` (optional)  
  - Enables verbose output (`Write-Verbose`) so you can see exactly what’s happening

- `-h`, `-Help` (optional)  
  - Shows usage information and exits  
  - Example: `.\Nessus-ScanToggle.ps1 -h`

---

### How to use 
- **Enable with scanner IP restriction (recommended for build review):**

  ```powershell
  .\Nessus-ScanToggle.ps1 -m Enable -s 10.0.0.5,10.0.0.6 -v



when nessus is run check for 104410 to ensure nessus is working
