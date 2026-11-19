# Python specifics
- SQL: f-strings, `%` or `+` building queries passed to `cursor.execute`, SQLAlchemy `text()` or `.raw()`/`extra()` in Django with interpolation. Safe: parameter tuples / bound parameters.
- Commands/code: `os.system`, `subprocess.*(..., shell=True)` with user input, `eval`, `exec`, `compile`, `__import__` on input.
- Deserialization: `pickle`/`cPickle`/`dill`/`shelve` loads of untrusted data, `yaml.load` without `SafeLoader`, `jsonpickle`, `marshal`.
- Templates: Jinja2 `Environment(autoescape=False)`, `render_template_string` with user input (SSTI), `Markup()`/`|safe` on user data, Django `mark_safe`.
- Web: Flask `debug=True`, Django `DEBUG = True`/`ALLOWED_HOSTS = ['*']`, missing `@login_required`/permission checks, `csrf_exempt`, open redirects via `redirect(request.args[...])`.
- Paths/files: `open(os.path.join(base, user))` without resolving and checking the base; `send_file` with user paths; `tarfile.extractall`/`zipfile` without member checks.
- SSRF: `requests.get(user_url)`, `urllib.request.urlopen(user_url)`. TLS: `verify=False`.
- Crypto: `hashlib.md5/sha1/sha256` for passwords, `random` for tokens (use `secrets`), hardcoded keys, `xml.etree`/`lxml` on untrusted XML (prefer defusedxml).
