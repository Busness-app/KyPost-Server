# Logging

KyPost must emit structured, privacy-safe application logs to standard output
and standard error. It must not build or require a KySecurity-specific log
database, log search system, or long-term retention service.

Operators may route the container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log authentication outcomes, MFA outcomes, rate limits, mail synchronization
failures, delivery failures, configuration changes, pairing, and administrative
actions. Use request IDs and coarse actor identifiers where useful.

Never log passwords, tokens, private keys, CAPTCHA answers, mail bodies,
subjects, attachment contents, IMAP credentials, or raw request bodies. Do not
expose log contents through a product-specific admin page; use the operator's
logging platform instead.

The existing local log files and log viewer are transitional compatibility
features. New work should write structured events and preserve the external
logging boundary.
