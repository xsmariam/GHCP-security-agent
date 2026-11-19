# C# / .NET specifics
- SQL: `SqlCommand` with concatenated `CommandText`, EF `FromSqlRaw`/`ExecuteSqlRaw` with interpolation (safe: `FromSqlInterpolated`, parameters).
- Commands: `Process.Start` with user-controlled file names or arguments; `cmd.exe /c`.
- Deserialization: `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, Json.NET `TypeNameHandling` other than `None`, `JavaScriptSerializer` with type resolver.
- XML: `XmlDocument`/`XmlTextReader` with `DtdProcessing.Parse` or an `XmlResolver` set.
- Web: missing `[Authorize]`, `[AllowAnonymous]` on sensitive actions, missing `[ValidateAntiForgeryToken]`, `Html.Raw` on user data, open redirects (`Redirect(returnUrl)` without `Url.IsLocalUrl`), over-posting/mass assignment.
- Files: `Path.Combine(base, user)` (absolute input overrides base), unchecked uploads.
- Crypto: MD5/SHA1 for passwords, `System.Random` for tokens (use `RandomNumberGenerator`), `ServerCertificateValidationCallback` returning true, DES/TripleDES/ECB.
