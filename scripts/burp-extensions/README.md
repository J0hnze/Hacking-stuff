# Burp Suite Extensions

Pre-downloaded extensions for environments without BApp Store access.

## Installation

In Burp Suite: Extensions > Installed > Add > Select file

## Extensions

| Extension | File | Type | Purpose |
|-----------|------|------|---------|
| Autorize | Autorize.py | Python | Authorization testing (IDOR/BAC) |
| ActiveScan++ | active-scan-plus-plus.jar | Java | Enhanced active scanning |
| JSON Escaper | json-escaper.py | Python | JSON payload encoding/escaping |
| JSON Unicode Escaper | json-unicode-escaper.jar | Java | Unicode escaping for JSON payloads |

## Retire.js (requires build)

Not available as pre-built jar. Build from source:

```bash
git clone https://github.com/h3xstream/burp-retire-js.git
cd burp-retire-js
mvn package -DskipTests
# jar: retirejs-burp-plugin/target/retirejs-burp-plugin-*.jar
```

## Notes

- Python extensions require Jython standalone jar configured in Burp (Extensions > Options > Python Environment)
- Java extensions (.jar) work directly
