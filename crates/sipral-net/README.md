# sipral-net

Part of [Sipral](https://sipral.org), the Session Initiation Protocol Rust Audio Layer: the optional networking component — UDP and TCP sockets, TLS with rustls against the platform's trust store, a private authority or one pinned certificate, and RFC 3263's NAPTR, SRV, A and AAAA lookups — for a program that drives the sans-I/O core directly and has no networking of its own. `docs/26-network.md` in the repository says what it does and does not do yet.

Nothing in `sipral` depends on it; a C or C++ program reaches it through the C library built with `sipral-ffi`'s `network` feature. Its API makes no compatibility promise between releases yet, and each Sipral release takes it at exactly its own version.

Dual-licensed AGPL-3.0 / commercial: <https://sipral.org/terms/>.
