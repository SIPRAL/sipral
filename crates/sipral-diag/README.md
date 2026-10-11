# sipral-diag

Part of [Sipral](https://sipral.org), the Session Initiation Protocol Rust Audio Layer: call records turned into pcapng, and personal data redacted out of them.

This crate is published because `sipral` depends on it, and is not meant to be named on its own. Its API makes no compatibility promise between releases: depend on [`sipral`](https://crates.io/crates/sipral), which names everything an application uses from here and keeps it the same across 1.x. Each release of `sipral` takes this crate at exactly its own version.

Dual-licensed AGPL-3.0 / commercial: <https://sipral.org/terms/>.
