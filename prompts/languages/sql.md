# SQL specifics
- Dynamic SQL (`EXEC`, `EXECUTE IMMEDIATE`, `sp_executesql`, `PREPARE ... FROM`) built by concatenating procedure parameters.
- Overly broad grants (`GRANT ALL`, `PUBLIC`), `SECURITY DEFINER` functions without a fixed `search_path`.
- Plaintext password or card columns; seeded default credentials.
