# JavaScript / TypeScript specifics (Node.js and browser)
- Injection: string-built SQL in `mysql`/`pg`/`sequelize.query`, NoSQL operators from request bodies in MongoDB queries (`{ $where }`, `$ne` objects), `child_process.exec`/`execSync` with input, `eval`, `new Function`, `vm.runInContext`, `setTimeout(string)`.
- XSS: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`, template engines with unescaped output (`<%- %>`, `{{{ }}}`, `!=`).
- Prototype pollution: recursive merge/`Object.assign`/lodash `merge`/`set` on user objects; `__proto__`/`constructor` keys.
- Express/Fastify/Next: missing auth middleware on routes, missing CSRF on cookie-auth state changes, `cors({ origin: true, credentials: true })` or `*` with credentials, missing `helmet`, trusting `req.query`/`req.body` for user IDs (IDOR), open redirects via `res.redirect(req.query.url)`.
- Files/SSRF: `path.join(base, req.params.x)` without checks, `res.sendFile` with user paths, `fetch`/`axios` with user URLs.
- Auth: `jwt.decode` instead of `verify`, `algorithms` not pinned, `none` alg, secrets in client bundles, tokens in `localStorage` on XSS-prone apps, `Math.random` for tokens (use `crypto.randomBytes`/`crypto.randomUUID`).
- ReDoS: catastrophic-backtracking regexes on user input. TLS: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`.
