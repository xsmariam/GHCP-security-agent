# Shell / PowerShell specifics
- Unquoted variable expansion (`$var` vs `"$var"`) leading to word splitting/globbing injection; `eval` of input; `Invoke-Expression`.
- `curl | sh`, downloads without checksum/signature verification; `curl -k`/`--insecure`.
- Secrets in scripts or passed on command lines (visible in process lists); `set -x` printing secrets.
- Predictable temp files (`/tmp/name`) instead of `mktemp`; `chmod 777`; running as root unnecessarily.
