# Runbooks
- **Release a control:** edit definition -> `make all` -> PR -> merge -> tag -> deploy in audit mode -> review impact report -> gate -> enforce by wave.
- **Mass false positive after enforce:** Azure set effect override to Audit (minutes); GCP re-apply with `mode = dry_run`; AWS detach the bundle from the affected OU. Record incident, add fixture, re-release.
- **Break-glass use:** alarm fires -> reviewer confirms ticket -> after-action review within 2 business days.
- **Exception expiry:** sweeper notifies owner 7 days before; if not recertified, exemption is removed and the finding reopens.
- **Policy drift:** nightly comparison of deployed vs intended (diagram 18); mismatches open tickets.
