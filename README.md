```
 ________ _______  ___  ___  ________      
|\_____  \\  ___ \|\  \|\  \|\   ____\     
 \|___/  /\ \   __/\ \  \\\  \ \  \___|_    
     /  / /\ \  \_|/_\ \  \\\  \ \_____  \  
    /  /_/__\ \  \_|\ \ \  \\\  \|____|\  \ 
   |\________\ \_______\ \_______\____\_\  \
    \|_______|\|_______|\|_______|\_________\
                                 \|_________|

        [ ASYNC CREDENTIAL TESTING FRAMEWORK ]
          written in rust. built for speed.
```

<div align="center">

[![CI](https://github.com/sayavdera/zeus/actions/workflows/ci.yml/badge.svg)](https://github.com/sayavdera/zeus/actions/workflows/ci.yml)
[![Tests](https://github.com/sayavdera/zeus/actions/workflows/tests.yml/badge.svg)](https://github.com/sayavdera/zeus/actions/workflows/tests.yml)
[![Security Audit](https://github.com/sayavdera/zeus/actions/workflows/security.yml/badge.svg)](https://github.com/sayavdera/zeus/actions/workflows/security.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

> **⚠️ LEGAL DISCLAIMER**
>
> This tool is for **AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY**.
> You may only use Zeus against systems you **own** or have **explicit written permission** to test.
> Unauthorized use is **ILLEGAL**. The author bears **ZERO** responsibility for misuse.
> By using this software you accept full legal and ethical responsibility for your actions.

---

## `> whoami`

**Zeus** is a modern async rewrite of [THC Hydra](https://github.com/vanhauser-thc/thc-hydra) in Rust — faster, safer, and more extensible. Built on top of Tokio's async runtime, it handles thousands of concurrent credential tests across 30+ protocols without breaking a sweat.

```
architecture: async/await + actor model
language:     rust (stable)
runtime:      tokio
protocols:    30+
patterns:     strategy, builder, observer, registry, facade
```

---

## `> ls -la features/`

```
drwxr-xr-x  async-engine/       tokio semaphore + joinset orchestration
drwxr-xr-x  attack-strategies/  dictionary | brute-force | hybrid | rule-based | markov | prince
drwxr-xr-x  protocol-plugins/   30+ protocols via registry pattern
drwxr-xr-x  crypto-primitives/  md5 | sha1/256/512 | hmac | ntlm | cram-md5
drwxr-xr-x  adaptive-timing/    jitter + rate limiting + lockout detection
drwxr-xr-x  checkpoint-resume/  save/restore attack sessions
drwxr-xr-x  fingerprinting/     service banner analysis
drwxr-xr-x  response-analysis/  smart success/failure detection
drwxr-xr-x  tui-interface/      ratatui real-time dashboard
drwxr-xr-x  structured-logging/ tracing + json/text output
drwxr-xr-x  config-system/      toml + env var override
```

---

## `> cat protocols.txt`

| Category   | Protocols                                                          |
|------------|--------------------------------------------------------------------|
| **Web**    | HTTP Basic/Digest · HTTP Form · HTTP Proxy · REST endpoints        |
| **Mail**   | SMTP · SMTP-ENUM · POP3 · IMAP · NNTP                             |
| **Remote** | SSH · Telnet · FTP · RSH · Rexec                                   |
| **Windows**| SMB · RDP · VNC                                                    |
| **Msg**    | IRC · XMPP · SIP · RTSP                                            |
| **DB**     | MySQL · PostgreSQL · Redis · MSSQL · MongoDB · Memcached · Oracle · Firebird |
| **Other**  | LDAP · SNMP · SOCKS5 · SVN · CVS                                   |

---

## `> tree zeus/`

```
zeus/
├── src/
│   ├── main.rs              # entry point — clap CLI
│   ├── cli/                 # subcommands
│   └── tui/                 # ratatui dashboard
│
├── zeus-core/               # core contracts: Protocol trait, Credential, Target
├── zeus-macros/             # proc-macros: #[ZeusProtocol] derive
├── zeus-net/                # tcp/tls, rate limiter, connection pool, proxy
├── zeus-proto/              # application protocol implementations
├── zeus-database/           # database protocol implementations
├── zeus-registry/           # thread-safe plugin registry (dashmap)
├── zeus-attack/             # dictionary, brute-force, hybrid, markov, prince
├── zeus-engine/             # async orchestration: adaptive, priority, multi-engine
├── zeus-crypto/             # hashing, hmac, ntlm, cram-md5, base64/hex
└── zeus-config/             # toml config + env var override
```

---

## `> zeus --help`

```bash
# list all available protocols
zeus list

# dictionary attack — ftp
zeus dict -H 192.168.1.1 -p 21 -P ftp -u admin,root -w /path/to/passwords.txt

# brute force — max 4-char alphanumeric
zeus brute -H 192.168.1.1 -p 21 -P ftp -u admin --max-len 4

# http form attack with custom params
zeus dict -H 10.0.0.1 -p 80 -P http-form -u admin -w rockyou.txt -c 64

# hybrid attack (wordlist + rules)
zeus hybrid -H 10.0.0.1 -p 22 -P ssh -u root -w base.txt --rules append-123

# resume a saved checkpoint
zeus resume --checkpoint ./zeus-checkpoint.json

# verbose + json output
zeus -v dict -H 10.0.0.1 -p 443 -P https -u admin -w passwords.txt --output json
```

---

## `> cat zeus.toml`

```toml
concurrency    = 64
timeout_secs   = 10
retry_count    = 2
retry_delay_ms = 300
exit_on_first  = true
verbose        = false

[output]
format = "json"        # text | json | csv
file   = "/tmp/zeus-results.json"

[timing]
min_delay_ms   = 0
max_jitter_ms  = 500
adaptive       = true  # auto-backoff on lockout detection
```

```bash
# env vars override config (separator: __)
ZEUS__CONCURRENCY=128 zeus dict ...
ZEUS__VERBOSE=true zeus list
```

---

## `> cargo build --release`

```bash
git clone https://github.com/sayavdera/zeus
cd zeus
cargo build --release
./target/release/zeus --help
```

**Requirements:** Rust stable (1.75+)

---

## `> cargo test --workspace`

```bash
cargo test --workspace --all-features
# coverage
cargo tarpaulin --workspace --out Html
```

---

## `> cat stack.txt`

| Crate                            | Role                          |
|----------------------------------|-------------------------------|
| `tokio`                          | async runtime                 |
| `reqwest`                        | http client                   |
| `tracing` + `tracing-subscriber` | structured logging            |
| `clap`                           | cli parsing                   |
| `ratatui` + `crossterm`          | terminal ui                   |
| `config`                         | toml/env config               |
| `sha2`, `md-5`, `sha1`, `hmac`   | crypto hashes                 |
| `dashmap`                        | concurrent registry           |
| `parking_lot`                    | fast mutex                    |
| `serde` + `serde_json`           | serialization                 |
| `async-trait`                    | async trait objects           |
| `thiserror` + `anyhow`           | error handling                |

---

## `> cat LICENSE`

MIT — see [LICENSE](LICENSE)

---

<div align="center">

```
[ zeus ] — use the lightning. responsibly.
```

*For authorized security testing and educational research only.*

</div>
