# ADR 0006: Private Key File Permissions

## Status
Accepted

## Context
Private key files (TLS server keys, CA keys) were being loaded directly without verifying their file permissions. In POSIX environments, if an administrator mistakenly extracts or copies a private key with world-readable permissions (e.g., `0644`), any local user could read the key and potentially compromise the system. The principle of fail-closed security requires that sensitive operations be restricted.

## Decision
We will enforce safe file permissions (`0600` or `0400`) on all loaded private key files (`CAKeyPath` and `ServerKeyPath`). 
To maintain backward compatibility and avoid breaking existing setups unexpectedly, this check defaults to a "warn-only" mode where a log message is printed but execution continues.
The check can be converted to a strict failure (halting the server) by setting `KUT_STRICT_KEY_PERMISSIONS=1`.
On Windows environments, where POSIX-style permissions do not natively apply, this check is bypassed via a `runtime.GOOS` guard.

## Consequences
- **Positive:** Reduces the risk of local key compromise by actively checking file permissions.
- **Positive:** Smooth rollout enabled by making the strict failure opt-in.
- **Negative:** Administrators on POSIX systems may need to fix their deployment scripts if permissions were previously relaxed.
