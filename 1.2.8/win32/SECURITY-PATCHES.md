# Security patches for memcached 1.2.8 (Win32 port)

Backported hardening and CVE fixes applied to this tree on top of the original
Kronuz/Brodie Win32 build of memcached 1.2.8. These change only the behavior
described below; the text protocol and all normal operations are unchanged.

Files touched: `memcached.c`, `memcached.h`, `thread.c`, `items.c`.

## 1. CVE-2010-1152 — unbounded input buffer

**Problem:** `try_read_command()` returned and kept buffering whenever it had
not yet seen a `\n`. A client could stream data forever with no newline and
force the server to keep doubling the per-connection read buffer until memory
was exhausted.

**Fix:** if more than 1 KB has accumulated with no newline, the line is only
allowed to continue when it is a legitimate large multiget (`get`/`gets`/`bget`,
after skipping up to 100 leading spaces). Anything else moves the connection to
`conn_closing`. Ported from the upstream 1.4.3 fix.

Verified: a 200 KB junk line, and 300 leading spaces followed by a bare `get`
with no newline, both close the connection instead of growing the buffer.

## 2. CVE-2018-1000115 — UDP reflection / amplification

**Problem:** the UDP listener defaulted to port 11211 (on). An open,
unauthenticated UDP port is the classic memcached DDoS amplification vector.

**Fix:** default `settings.udpport` changed from `11211` to `0` (off). UDP is
now opt-in with `-U <port>`. Usage text updated to match.

Verified: no UDP responder on 11211 by default.

## 3. `-m` integer overflow (32-bit)

**Problem:** `settings.maxbytes = ((size_t)atoi(optarg)) * 1024 * 1024;` is
computed in a 32-bit `size_t` on this build. `-m 4096` wrapped to `0`, which
means *no* memory limit — the opposite of the operator's intent — and
`atoi()` accepted non-numeric input as 0.

**Fix:** parse with `safe_strtoul()`, reject non-numeric input, and reject any
value whose product would wrap `size_t` (> ~4095 on 32-bit). The server now
exits with a clear error instead of silently running uncapped.

Verified: `-m 4096` and `-m abc` are rejected; `-m 1024` yields
`limit_maxbytes 1073741824`.

## 4. Strict numeric parsing of client commands

**Problem:** `set/add/replace/cas/incr/decr/delete/flush_all` parsed numbers
with `strtol/strtoul/strtoull/strtoll` and checked only `errno == ERANGE`.
On this port that check is dead code: `win32.h` does `#define errno werrno()`,
remapping `errno` to the last Winsock error, so range/format errors were never
detected. Separately, `win32.h` did `#define strtoull strtoul`, silently
truncating 64-bit CAS IDs and `incr`/`decr` values and deltas to 32 bits.

**Fix:** added `safe_strtoull()`, `safe_strtoul()` and `safe_strtol()` helpers
(in `memcached.c`) that do their own base-10 parsing with explicit overflow
detection and reject trailing garbage, independent of `errno`. All the command
handlers now use them. `do_add_delta` / `mt_add_delta` delta parameters are now
`uint64_t` end to end (`memcached.c`, `memcached.h`, `thread.c`), restoring true
64-bit arithmetic.

Also hardened the `set`/`cas` value length: a length `< 0` or `> INT_MAX - 2`
is rejected before `vlen + 2` is used. Previously a crafted length could become
negative or overflow and be passed to the `conn_swallow` read path as a huge
size, overflowing the heap read buffer.

Verified: non-numeric and out-of-range lengths, flags, CAS ids, deltas and
delays are rejected with `CLIENT_ERROR`; the connection stays usable; 64-bit
counters round-trip; and a `set` with length `2147483647` is rejected and the
server survives a following multi-megabyte payload (the unpatched build crashes
with an access violation on the same input).

## 5. `stats cachedump` out-of-bounds read

**Problem:** `do_item_cachedump()` guarded with `if (slabs_clsid > LARGEST_ID)`.
`heads[]` has exactly `LARGEST_ID` (255) elements (indices 0–254), so a slab
class id of 255 passed the check and read `heads[255]`, one past the array.

**Fix:** guard changed to `>= LARGEST_ID`.

Verified: `stats cachedump 255 0` now returns `SERVER_ERROR`.

## Not applicable

- **CVE-2009-1255** (`stats maps` info leak): the `stats maps` subcommand is
  already compiled out on `WIN32`, so nothing to do.

## Build / test notes

Patched source was built Release/x86 and exercised with a protocol + security
regression client covering all of the above against both the unmodified
baseline and the patched binary. The shipped Visual Studio project targets the
v110 (VS2012) toolset; these are source-only changes and add no new files to
the build.
