# Configuration / infrastructure specifics
- App config: debug/dev mode enabled, verbose errors, permissive CORS (`*` with credentials), disabled CSRF, default or hardcoded credentials, insecure cookie flags (missing Secure/HttpOnly/SameSite), HTTP instead of HTTPS endpoints.
- Spring `application.yml`/`.properties`: actuator endpoints exposed (`management.endpoints.web.exposure.include=*`), H2 console enabled.
- Docker: running as root (no `USER`), `latest` tags, secrets in `ENV`/`ARG`, `ADD` from remote URLs, `--privileged`, mounting the Docker socket.
- Kubernetes/Compose: `privileged: true`, `hostNetwork`, `hostPath`, `allowPrivilegeEscalation`, missing resource limits, secrets in plain manifests.
- Terraform/cloud: public buckets/ACLs, `0.0.0.0/0` on admin ports, unencrypted storage, wildcard IAM actions/resources, logging disabled.
- Build files: plugins or dependencies fetched over HTTP; only flag specific dependency versions as vulnerable if you are confident and say so in assumptions (no live CVE lookup was performed).
