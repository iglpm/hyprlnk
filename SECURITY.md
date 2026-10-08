# Security policy

## Supported versions

Security fixes go into the latest release. hyprlnk follows Rune's version
numbers (`YEAR.MINOR.PATCH`); within a year's line, upgrading is always
compatible.

## Reporting a vulnerability

Please don't open a public issue. Report it privately through GitHub:
the repository's **Security** tab → **Report a vulnerability**
(<https://github.com/runepm/hyprlnk/security/advisories/new>).

Include what you found, how to reproduce it (a `/REPRODUCE` archive or the
input files, if you can share them), and what an attacker could do with it.
You'll get an acknowledgement within a few days and updates until it's
resolved; we'll credit you in the advisory unless you'd rather not be.

## Scope

A linker reads object files and libraries, which may come from third
parties (dependencies, prebuilt libraries). In scope:

- memory unsafety, crashes or hangs caused by malformed inputs;
- images that don't match their inputs (wrong code or data written, missing
  security flags such as ASLR or DEP that were asked for);
- anything that writes outside the output paths it was given.

Linking a malicious library into your program is out of scope: linking it
gives it your program's privileges, by design.
