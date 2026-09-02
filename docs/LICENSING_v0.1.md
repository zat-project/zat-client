# ZAT — licensing & GPL compliance (v0.1)

**Decision date:** 2026-07-11 · **Owner:** Sam · resolves master-plan risk **L-1**.

## The obligation

The distributed **Android client** bundles **sing-box / `libbox`** (`lib/<abi>/libbox.so`), which is
**GPL-3.0-or-later** (SagerNet/sing-box), with **no linking exception and no commercial/dual license** — a
commercial license cannot authorize embedding it in a proprietary product, and a closed-source app that
ships `libbox.so` is a GPL violation (there is public precedent, e.g. "TipTop VPN"). The client links
`libbox` **in-process** (JNI), which under the GPL makes the client a **combined/derivative work** →
its corresponding source must be available under the GPL.

The **broker** does not use sing-box and is a **network service that is never distributed** to users, so
the GPL is **not triggered** for it. The **volunteer app** runs `sing-box` as a **separate process**
(subprocess + its own config file — arm's-length "mere aggregation", not linking), so the volunteer's own
code is **not** a derivative; it must only make the (unmodified, upstream) sing-box source available.

## Resolution — a hybrid license map

| Component | Distributed in the client APK? | License |
|---|---|---|
| `client-android/zat-app`, `client-android/zat-connection-manager` (the Kotlin client that links `libbox`) | **Yes** — the GPL trigger | **GPL-3.0-or-later** (`client-android/COPYING`) |
| `client-android/mesh-oprf-rs`, `zat-oprf-client`, `zat-threshold-oprf` (the client's + shared crypto compiled into `libmeshoprf.so`) | **Yes** (native), but ALSO used by the closed broker/volunteer | **MIT** (`LICENSE-MIT`; `zat-oprf-client`/`zat-threshold-oprf` already declared it) — GPL-compatible (usable inside the GPL client) yet permissive (usable in the closed components), so it does NOT force the volunteer/broker to GPL |
| `broker`, `volunteer-app`, `volunteer-app-ui`, `zat-dht-node`, `zat-dkg`, `zat-threshold-sign`, `docs/` | **No** — never in the client APK | **Proprietary / all rights reserved** (not published) |
| `libbox.so` (sing-box) | Yes | **GPL-3.0-or-later**, © SagerNet — upstream, unmodified |

**Why this is both compliant and safe (aligns with master-plan §5.9 / Kerckhoffs):** the client is a
"dumb" consumer — fetch the signed snapshot, verify its signature, connect via `libbox`. **The security-
sensitive logic (oblivious matching, the L3 gate, traitor-tracing, the committee, anti-enumeration) lives
in the BROKER + the protocol + the signed snapshot — all of which stay closed.** Opening the client hands
the censor nothing it cannot already extract by reverse-engineering the shipped binary (secrecy buys time,
not safety), and source availability is a **trust asset** for a tool that asks people to route traffic.

## sing-box attribution (required)

sing-box is © the SagerNet contributors, GPL-3.0-or-later, from <https://github.com/SagerNet/sing-box>.
The GPL grants no permission to use the sing-box **name/branding** or imply association without consent —
so ZAT must not present itself as sing-box or a sing-box product. `libbox` is vendored **unmodified** from
a pinned tag (see `client-android/sing-box-libbox/Dockerfile`); its corresponding source is that pinned
upstream tag.

## Providing the corresponding source (GPL §6)

Every recipient of a client binary must be able to get the **corresponding source** of the GPL parts. Plan:
publish the client source (`client-android/zat-app` + `client-android/zat-connection-manager` + the
MIT crypto crates + the `libbox` build recipe) in a **public repository**, and link it from the app's
About screen + every download/release page. The **reproducible native-libs build** (`docs/TECH_DEBT.md`
F2 — `build.sh` + the pinned Dockerfile) lets anyone rebuild the exact `libbox.so`/`libmeshoprf.so` and
verify the published binary against the source. **Action (Sam):** create the public client repo (or attach
a source tarball to each release) before the first public distribution.

## What stays closed

The broker and its deployment, the volunteer bridge/committee crates (`zat-dht-node`, `zat-dkg`,
`zat-threshold-sign`) and the volunteer desktop app are **not distributed to end users** and are **not**
under the GPL — they remain proprietary. The volunteer app additionally **bundles `sing-box.exe`
(unmodified)**, so its installer must ship (or link) the upstream sing-box source to satisfy the GPL for
that binary, while the volunteer's own Rust/Tauri code stays closed.
