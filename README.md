# DarkSpam

DarkSpam is a sendmail/postfix milter written in C that connects your MTA to
SpamAssassin (spamd). It was born on a production mail server and grew for
years around one idea: the milter should do the cheap work itself, feed
SpamAssassin only what is worth scanning and always leave a trace of what it
decided and why.

Version 1.0. Part of the DarkGlobe project.
Source: https://github.com/darkglobe-project/darkspam

## Why another SpamAssassin milter

Most SpamAssassin milters are thin pipes: they push the whole message to
spamd, read a score and either reject or pass. DarkSpam differs in several
ways that matter on real traffic:

* **Streaming MIME filter.** Other milters cap the amount of data sent to
  spamd with a blind byte limit, typically truncating after the first body
  chunk. DarkSpam instead parses the MIME structure on the fly with a
  four state automaton and forwards only the parts that SpamAssassin can
  actually use: text parts, part headers and the multipart skeleton.
  Binary attachment bodies are dropped selectively. Constant memory,
  no temporary files, no full message buffering.
* **Policy before scanning.** A single Berkeley DB access table drives
  per connection, per sender and per recipient decisions before spamd is
  ever contacted. Trusted traffic never pays the scanning cost.
* **Real multi recipient handling.** Most milters treat the envelope as if
  it had one recipient. DarkSpam records every RCPT with its own access
  verdict and applies a per recipient policy at end of message, including
  selective recipient removal on spam.
* **Nothing is silent.** Every message that skips scanning gets an
  X-DarkSpam header stating the reason and a log line saying which access
  entry decided. The classic mystery of "why is there no X-DarkSpam on
  this mail" does not exist here.
* **Fail open by design.** If spamd is down, times out or answers garbage,
  mail flows. Every degradation is logged at warning level so the operator
  sees it, but delivery never depends on the scanner being healthy.

## Features

### 1. Reject or tag

By default spam is rejected during the SMTP transaction with a 554 reply,
so no backscatter is ever generated. With the `-t` option DarkSpam switches
to tagging mode: spam is accepted, marked with `X-Spam-Flag: YES` and an
`X-DarkSpam` header carrying the score, and delivery proceeds. Webmail and
client side rules can then file it into a spam folder. Clean mail always
receives an `X-DarkSpam` header with score, elapsed scan time and scanning
host. Headers are deliberately kept short: DarkSpam does not copy the full
SpamAssassin report into the message.

### 2. Access table policy

DarkSpam reads the standard sendmail `access.db` (Berkeley DB hash) and
honours the usual states plus its own tags:

```
OK, RELAY, FRIEND        accept (skip scanning)
REJECT, ERROR            reject during SMTP
DISCARD                  accept and drop silently
SKIP                     stop the search and scan normally
```

Lookups are performed on the connecting IP, the reverse hostname, the
envelope sender and every envelope recipient. Generic entries work as in
sendmail; the dedicated `DS-Connect:`, `DS-From:` and `DS-To:` tags let you
write rules that apply to DarkSpam only, without touching the entries your
MTA already uses. Example:

```
Connect:1.2.3.4              RELAY
Connect:2.2.3                RELAY
192.178.1                    REJECT
DS-From:adomain.com          OK
DS-To:italiandomain.it       SKIP
DS-To:darkg@mydomain2.com    RELAY
DS-From:JohnBlue@6612.com    REJECT
dns.mydomain.com             RELAY
Spam:mrx@mydomain.com        FRIEND
```

IP entries are searched with progressive reduction, so `Connect:2.2.3`
matches the whole 2.2.3.0/24. Domain entries are reduced one label at a
time. The table is reloaded automatically when the file changes and on
SIGHUP or SIGUSR1.

### 3. IPv4 and IPv6

IPv6 entries use the compressed canonical form (RFC 5952, lowercase) with
the `IPv6:` prefix and are searched with a reduction ladder that never
crosses the `::` ellipsis, so a host entry can never accidentally match a
different address:

```
DS-Connect:IPv6:2001:db8::1      RELAY     exact host
Connect:IPv6:2001:db8::          OK        whole block behind the ellipsis
IPv6:fd00:aa                     REJECT    prefix, two groups
DS-Connect:IPv6:::1              FRIEND    loopback (note the three colons)
```

Bracketed literals such as `[IPv6:2001:db8::1]` are matched through the
hostname channel, exactly as sendmail does. IPv4 mapped addresses arriving
on dual stack sockets (`::ffff:a.b.c.d`) are detected in binary form and
routed to the IPv4 rules, so existing IPv4 entries and the connection
whitelist keep working unchanged.

### 4. Streaming MIME filter

Enabled by default, disabled with `-M`. The automaton has four states:
outside the parts everything passes, part headers always pass untouched,
text bodies pass, declared binary bodies are consumed. The decision is
made by exclusion: `text/*` is kept, `multipart/*` is descended into,
`message/*` is rescanned so that an embedded message with its own inner
multipart is handled correctly, and anything else that is explicitly
declared is dropped. A part with no Content-Type at all keeps the benefit
of the doubt and is forwarded, letting SpamAssassin judge.

Two consequences worth spelling out:

* Part headers are never filtered, so all the SpamAssassin rules that look
  at Content-Type, filenames, double extensions and MIME structure keep
  their full signal. What disappears is only the encoded body of images,
  archives and documents, which the scoring engine cannot read anyway.
  Antivirus scanning belongs to a different stage of the chain and sees
  the intact message.
* The size limit (`-z`) is applied to the bytes actually forwarded to
  spamd, not to the wire size. A ten megabyte message with two paragraphs
  of text and a huge attachment used to skip scanning entirely because it
  exceeded the limit. With the filter it forwards a few kilobytes and gets
  scanned. This is the opposite of the brutal truncation used elsewhere:
  the cut is structural, not positional.

No decoding is performed. Kept parts travel verbatim with their original
Content-Transfer-Encoding and SpamAssassin decodes them itself, so the
message spamd receives is still valid MIME, just thinner.

### 5. Multiple recipients

Providers behave differently: some split a multi recipient submission into
separate messages, others deliver the whole envelope in one transaction.
DarkSpam handles the second case properly instead of pretending the first
recipient speaks for everyone:

* Rejecting entries act per recipient during the RCPT phase, refusing only
  the recipient they match while the transaction continues for the others.
* Scanning is skipped only by unanimity: every recipient of the envelope
  must be whitelisted. A single whitelisted address can no longer be
  abused as a passe partout to smuggle unscanned mail to everyone else.
* On a spam verdict with a mixed envelope, recipients that wanted
  filtering are silently removed from delivery (for them the alternative
  was a reject) while whitelisted recipients, who asked to receive
  everything, get the message tagged. The removal is logged at notice
  level with the full list of removed addresses.
* Connection level and sender level whitelisting always prevail: mail from
  a trusted host or sender skips scanning for all recipients.

### 6. Everything else

* Runtime log levels with `-l`, syslog mask based. Level 7 activates the
  full historical debug tracing on a production binary, no recompilation.
* MIME filter summary in the logs: parts kept, parts dropped and bytes
  filtered out, per message.
* Verdict lines carry sender, recipient (with a `(+N others)` compaction
  for multi recipient envelopes), score, threshold and elapsed time.
* spamd address and port configurable at runtime with `-m`.
* Connection whitelist regex configurable with `-w`, empty string to
  disable.
* Foreground mode with `-f` for debugging and systemd.
* Validated command line parsing: an invalid `-z` value aborts at startup
  instead of silently disabling scanning.
* Strict memory discipline: per connection context, preallocated recipient
  table growing in batches, constant memory MIME parsing, no temporary
  files.

## Installation

### Building

Requirements: gcc, libmilter (sendmail development package) and Berkeley
DB. On Debian and derivatives:

```
apt-get install build-essential libmilter-dev libdb-dev
make
```

The build produces a single `DarkSpam` binary from three sources:
`DarkSpam.c` (milter logic), `DB.c` (access table lookups) and `Parse.c`
(pure parsing functions: IPv6 normalization and the MIME automaton).

### Default paths

```
milter socket     unix:/var/spool/DarkSpam/sock     (option -p)
access table      /etc/mail/access.db
spamd             127.0.0.1:783                     (option -m)
run as user       smmsp                             (option -u)
```

Create the socket directory owned by the milter user before the first
start:

```
mkdir -p /var/spool/DarkSpam
chown smmsp /var/spool/DarkSpam
```

### Command line options

```
-z <bytes>       maximum size forwarded to spamd per message
                 (default 131072, counted after the MIME filter)
-u <user>        user to drop privileges to (default smmsp)
-U <user>        value of the User: header sent to spamd (default smmsp)
-p <socket>      milter socket, unix:/path or inet:port@host
-m <ip[:port]>   spamd address in dotted quad (default 127.0.0.1:783)
-w <regex>       connection whitelist, extended regex matched against IP
                 and hostname; empty string disables it
-l <0-7>         syslog level: 4 warning, 5 notice (default), 6 info,
                 7 debug. Debug lines use the daemon facility, so the
                 syslog daemon must record daemon.debug to show them
-t               tag spam (X-Spam-Flag: YES) and deliver instead of
                 rejecting with 554
-M               disable the streaming MIME filter
-f               stay in foreground (debugging, systemd)
-h               help
```

Both `-l 7` and `-l7` forms are accepted for options with a value.

### Sendmail configuration

Place DarkSpam prudently after the verification filters (SPF, DKIM, DKIM2,
ARC and DMARC). Milters run as a pipeline: each one sees the message as
modified by the previous ones, and DarkSpam adds headers and, in the mixed
recipient case, alters the envelope. Verifiers must therefore judge the
message before DarkSpam touches it, and signing filters must run after it
so that they sign what is actually being sent. A working `.mc` fragment:

```
define(`confMILTER_MACROS_CONNECT', `{client_addr}, {client_name}, {client_ptr}, {j}, {daemon_name}, {auth_type}')
define(`confMILTER_MACROS_HELO', `{tls_version}, {cipher}, {cert_subject}, {cert_issuer}')dnl
define(`confMILTER_MACROS_ENVFROM', `i, {auth_type}, {auth_authen}, {auth_ssf}, {auth_author}, {mail_addr}, {mail_host}, {mail_mailer}')dnl
define(`confMILTER_MACROS_ENVRCPT', `{rcpt_addr}, {rcpt_host}, {rcpt_mailer}')dnl
define(`confMILTER_MACROS_EOM', `{msg_id}')dnl
define(`confPRIVACY_FLAGS',`goaway,noreceipts,nobodyreturn')
dnl # 1. VERIFY - at the top of the chain to see the intact message
INPUT_MAIL_FILTER(`smf-spf', `S=unix:/var/run/smfs/smf-spf.sock, T=S:30s;R:1m')dnl
INPUT_MAIL_FILTER(`opendkim', `S=local:/run/opendkim/opendkim.sock')
INPUT_MAIL_FILTER(`opendmarc',`S=local:/run/opendmarc/opendmarc.sock, F=T')dnl
INPUT_MAIL_FILTER(`DarkARC',
                   `S=unix:/var/spool/DarkARC/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkChain',
                   `S=unix:/var/spool/DarkChain/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkSpam',
                   `S=unix:/var/spool/DarkSpam/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkARCs',
                   `S=unix:/var/spool/DarkARCs/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkChains',
                   `S=unix:/var/spool/DarkChains/sock, T=S:30s;R:2m')
```

Note that no `F=` flag is set on DarkSpam: if the milter fails, mail flows.

### systemd

```
[Unit]
Description=DarkSpam milter
After=network.target spamd.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/DarkSpam -f
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Making SpamAssassin fast enough

SpamAssassin is precise and slow. On the reference server, scan times
routinely broke the one second barrier before tuning. The table below
shows the per message timing breakdown measured with
`spamassassin -D -t < msg.eml`, before and after the work described here
(init and rule compilation are excluded since spamd pays them once at
startup):

```
component                 before      after
DNS bound tests (pri -100)  222 ms     93 ms
SPF check                   182 ms     48 ms
DNS idle polling            117 ms      0 ms
rule engine (pri 0)         816 ms    808 ms
Bayes auto learn            313 ms   journal
```

What was done, in order of yield:

1. **Delegate authentication to dedicated C milters.** DKIM verification
   and ARC belong to OpenDKIM and to the DarkGlobe milters at the top of
   the chain, where the message is intact. The SpamAssassin DKIM and DMARC
   plugins were disabled: with the MIME filter active the body reaching
   spamd differs from the original by construction, so any signature check
   there is deterministic garbage, and a DMARC evaluation without its DKIM
   leg would produce false failures on forwarded mail.

2. **Cut the slow DNS lists.** Two blocklists and one accreditation list
   answered in 400 to 900 ms while zen and spamcop answered under 100.
   Since DNSBL queries run in parallel, the slowest list sets the waiting
   wall for all of them. Three lines in `local.cf` removed them:

   ```
   dns_query_restriction deny surriel.com
   dns_query_restriction deny isipp.com
   dns_query_restriction deny fmb.la
   ```

   Also make sure a caching resolver runs locally: Spamhaus refuses
   queries coming from public resolvers, so pointing resolv.conf at
   8.8.8.8 silently loses the best signal available.

3. **Move Bayes writes out of the hot path.** `bayes_learn_to_journal 1`
   plus a nightly `sa-learn --sync --expire` cron run as the spamd user
   and `bayes_auto_expire 0` in `local.cf`.

4. **Compile the body rules.** `sa-compile` with the Rule2XSBody plugin,
   rerun after every `sa-update`.

5. **Let the MIME filter do its job.** The image spam wave that justified
   heavy image analysis peaked more than a decade ago; today the spam that
   matters travels as text and URLs because it needs to be clicked, and
   those always reach spamd. Dropping the encoded bodies of attachments
   cuts transfer and parsing time drastically without touching the
   headers the rules rely on. This is not a brutal byte cap: the cut is
   selective and structural, which is why the interesting text of a large
   message still gets scanned instead of being truncated away.

The remaining cost is the rule engine itself on modern link heavy
commercial mail, which is the price of the SpamAssassin corpus.

## About

DarkSpam is developed by Vittorio Moccia, who is also the author of
DarkChain, the first implementation of the DKIM2 standard as described in
[draft-moccia-dkim2-deployment-profile](https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/),
part of the [DarkGlobe Suite](https://github.com/darkglobe-project/darkglobe-suite)
dedicated to mail authentication.

DarkSpam source: https://github.com/darkglobe-project/darkspam

Copyright (c) 2026 Vittorio Moccia 
Licensed under the PolyForm Noncommercial License 1.0.0.
https://polyformproject.org/licenses/noncommercial/1.0.0
