# Logging

Go application logs use `ky-primitives/logging` JSON lines on stderr. `KY_LOG_LEVEL`
accepts debug, info, warn or error (default info); malformed values refuse startup.
Every line includes app, timestamp, level and RFC 5424 severity/facility. Backup
administrative events use authpriv; the flat SQLite backup audit remains separate.

The shared handler admits declared fields, caps string values and replaces control
characters. Undeclared fields are dropped and counted in `dropped_fields`. KyPost's
existing flat-string logger retains its sensitive-field redaction before this filter.
The allowlist bounds field names, not the meaning of values: callers must keep
passwords, tokens, private keys, CAPTCHA answers and correspondence out of messages
and diagnostic errors too. A source-harvesting regression test checks all production log keys against the declarations. Raw classifier output and upstream error bodies are never logged; warmup, retries and failures retain operation/status context at the default level.

The process opens no application log files or log-shipping sockets. Supervisord
captures and rotates `api.err.log` and `daemon.err.log`; the existing admin log
viewer defaults to the API stream. Historical app/classifier files remain readable
but receive no new output. Ollama and supervisord retain their own diagnostic logs.
Operators can collect captured streams with their existing logging agent. Direct
binary deployments collect stderr with their service manager.

The viewer is a transitional compatibility feature, not a new log platform.
