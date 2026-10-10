# Changelog DarkSpam

## [1.1 - 10/10/2026]

### Fixed

- **Undefined behaviour in case folding.** Three `tolower()` calls lacked
  the `(unsigned char)` cast: `ca_domain`, `ca_email` and `ca_emai_tmp` are
  `char` arrays, and `char` is signed on the usual targets, so any octet
  >= 0x80 reached `tolower()` as a negative int. The C standard leaves that
  undefined; glibc tolerates it by accident of table layout, another libc
  need not. A hostname or address carrying UTF-8 or Latin-1 is enough to
  reach it, so this was live on ordinary mail.

- **C locale pinned.** `main()` now calls `setlocale(LC_ALL, "C")`. Domains
  and addresses are lowercased before the access.db lookup and states are
  matched with `toupper()`; under a single-byte LC_CTYPE those routines map
  octets >= 0x80, so two different domains could fold to the same key and
  match the wrong access.db entry.

## [1.0]

Initial published release. 
