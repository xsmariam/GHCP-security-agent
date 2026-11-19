# Java / JVM specifics (Java, Kotlin, Scala, Groovy, JSP)
- SQL: `Statement.execute*` with string concatenation vs `PreparedStatement` with bound `?` parameters; JPA/Hibernate `createQuery`/`createNativeQuery` built from strings; MyBatis `${}`.
- Commands: `Runtime.exec`, `ProcessBuilder` with `sh -c`/`cmd /c` or user-controlled arguments.
- Deserialization: `ObjectInputStream.readObject`, `XMLDecoder`, Jackson default typing / `@JsonTypeInfo(use = CLASS)`, XStream, SnakeYAML `new Yaml()` without `SafeConstructor`.
- XML: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory` without disabling DTDs/external entities.
- Paths: `new File(base, userInput)`, `Paths.get` without `normalize()` + `startsWith(root)`; `ZipEntry` names on extraction.
- Spring: endpoints missing `@PreAuthorize`/security config, `csrf().disable()`, `permitAll()` on sensitive routes, `@CrossOrigin("*")`, SpEL from user input, mass assignment with `@ModelAttribute` on entities.
- Crypto: `MessageDigest` MD5/SHA-1/SHA-256 for passwords (use bcrypt/scrypt/Argon2/PBKDF2), `Cipher.getInstance("AES")` (ECB default), DES, static IVs, `java.util.Random` for tokens (use `SecureRandom`), trust-all `TrustManager`/`HostnameVerifier`.
- Output: writing request data into HTML responses without encoding; JSP `<%= %>` and `${}` without `fn:escapeXml`/`c:out`.
- Logging: credentials or tokens in `log.info`/`printStackTrace` sent to clients.
