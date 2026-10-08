# ADR-0001: Secret Environment Variable Clearing

## Status
Accepted

## Context
The KUT Security Suit C2 server reads sensitive configuration values, such as the master encryption key (`KUT_MASTER_KEY`) and database connection string (`KUT_DATABASE_URL`), from environment variables or file-based secret providers during startup. Once the configuration is loaded and the secrets are parsed into memory, these environment variables remain in the process environment. 

This poses a security risk. If a crash occurs resulting in a core dump, or if a child process is spawned (subprocess inheritance), or if an attacker gains arbitrary file read access (e.g., reading `/proc/environ` in Linux environments), these sensitive values could be exposed.

## Decision
We decided to implement a mechanism (`clearSecretEnv()`) that immediately unsets all sensitive environment variables (and their `_FILE` counterparts) right after they are successfully read and validated in the `config.Load()` function.

## Consequences
- **Positive:** Reduces the attack surface by ensuring that secrets do not persist in the process environment longer than necessary. Mitigates the risk of secret leakage through core dumps, `/proc/environ` reads, or accidental inheritance by child processes.
- **Negative:** If a process needs to be reloaded or if a library relies on these environment variables later in the execution lifecycle, it will fail. However, our configuration is parsed once at startup and stored in a struct, so this is an acceptable and intended restriction. Test cases had to be updated to account for environment mutations.
