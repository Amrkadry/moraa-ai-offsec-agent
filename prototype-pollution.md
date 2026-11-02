# Moraa — Prototype pollution (client → XSS, server → RCE/authz)

> HackTricks `nodejs-proto-prototype-pollution`. Cross-ref [[xss]] (PP→DOM XSS gadget),
> [[rce-scenarios]] (server PP→RCE), [[js-analysis]] (find merge sinks in bundles).

## Detect
Inject a pollution payload, then check whether a **fresh empty object inherits the property**.
- **Server-side (JSON body):** `{"__proto__":{"polluted":"yes"}}` or `{"constructor":{"prototype":{"polluted":"yes"}}}` → then hit any endpoint and look for behavior change / reflect `({}).polluted`.
- **Query/form (dot or bracket):** `?a[__proto__][polluted]=yes`, `?a.__proto__.polluted=yes`, `?constructor[prototype][polluted]=yes`.
- **Client-side:** URL/hash/`postMessage` merged via `$.extend`, Lodash `merge/set/defaultsDeep`, `Object.assign` on nested, query-string parsers. Confirm in console: `Object.prototype.polluted`.
Vulnerable primitives: recursive **merge/clone/extend**, `_.set(obj, userPath, val)`, `JSON.parse`→deep-merge, config loaders.

## Payload shapes
```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
{"__proto__.x":"y"}            // some flat parsers
```
`__proto__` is stripped by some sanitizers → use `constructor.prototype`. Blocked keys → try
`constructor[prototype]`, unicode, or duplicate keys.

## Escalate (PP alone = often just a DoS/flag; the GADGET is the finding)
| Target | Gadget → impact |
|---|---|
| **Auth/logic check** `if(user.isAdmin)` | pollute `Object.prototype.isAdmin=true` → **authz bypass** |
| **Template engine** (Handlebars/Pug/EJS) | pollute AST/compiler options (`type:"Program"`, `outputFunctionName`, `compilerOptions`) → **server-side RCE** |
| **Node `child_process`** | pollute `NODE_OPTIONS`/`shell`/`env`/`argv0` options consumed by `spawn`/`exec` → **RCE** |
| **DOM sink** | pollute `ownerDocument`/attribute defaults so a later `innerHTML`/template renders `<svg onload=...>` → **DOM XSS** ([[xss]]) |
| **`fetch`/`http` options** | pollute `headers`/`proxy`/`host` defaults → **SSRF / request smuggling** |
| **Missing-property defaults** | pollute a config default (`json spaces`, `content-type`) → response manipulation |

## Confirm & report
1. show the pollution took (`{}.x` returns your value / behavior changes), 2. reach a concrete gadget
(admin bypass 200, RCE output, XSS fires), 3. state scope (global `Object.prototype` for the process).
PP that pollutes but reaches no gadget = Low; find the gadget or it's not real impact.

## Server-side detection trick (no source)
Send `{"__proto__":{"status":599}}` / pollute a value the framework echoes (e.g. JSON spaces, a header)
and diff the response — a formatting/behavior change with no obvious param = server-side PP present.
Tools: PortSwigger **"Server-Side Prototype Pollution Scanner"** (Burp BApp), `ppmap`, `pputils`.
