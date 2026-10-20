# lockbox docs

Deeper material for people who want to know how lockbox works, work on it, or port it. To install and use lockbox, start with the [README](../README.md).

| Doc | For |
| --- | --- |
| [security.md](security.md) | The threat model, vault encryption and file format, Touch ID (Secure Enclave), the password backoff, locking, clipboard privacy, backups, and the rules that keep the attack surface small |
| [architecture.md](architecture.md) | How the Rust backend and the web UI fit together, every IPC command, the main flows, and the in-app updater |
| [development.md](development.md) | Building, testing, the release checks, adding a command, and dependency rules |
| [plans/](plans/) | Porting to [Windows](plans/windows.md) and [Linux (Debian)](plans/linux-debian.md): what's macOS-specific today and what each piece needs elsewhere |
| [history/](history/) | [The original brief](history/brief.md), kept unchanged, and [how lockbox was built](history/milestones.md), milestone by milestone |

**About "BRIEF §n" references:** comments in the code, such as "BRIEF §6.3", point to sections of [history/brief.md](history/brief.md). It's a historical record; where it differs from today's behaviour, the docs above are current.
