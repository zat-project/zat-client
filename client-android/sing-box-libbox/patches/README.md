# Local patches to sing-box's dependencies

The library this directory builds (`libbox`, from sing-box — GPL-3.0-or-later) is **modified**. This
file is the notice GPL-3.0 §5(a) asks for: what was changed, why, and when.

## `0001-sing-tun-pass-nil-attach.patch`

- **What:** `github.com/sagernet/sing-tun` `v0.8.10`, `stack_gvisor_filter.go`,
  `LinkEndpointFilter.Attach`. Seven lines are added — four of code, three of comment. When the
  dispatcher passed in is `nil`, the call is forwarded to the wrapped endpoint as `nil` and returns;
  the non-nil branch is unchanged.
- **Why:** sing-tun stops its gVisor stack by calling `Attach(nil)` on this wrapper. The wrapper used to
  wrap even a nil dispatcher in a non-nil filter, so gVisor's `fdbased` endpoint never saw `nil` and
  never ran the branch that stops its tun reader and waits for it. The reader then stayed blocked in
  `poll` on the tun after the app had closed every descriptor, and Android kept the VPN interface up —
  after the user pressed Disconnect, for as long as nothing happened to send a packet into the dead
  tun. With the patch the reader stops inside the stop call.
- **When:** 2026-09-24, for the ZAT Android client.
- **How it is applied:** `../Dockerfile` downloads sing-tun `v0.8.10` through the Go module proxy (checked
  against `go.sum`), copies it, applies this file with `patch -p1 --fuzz=0` after checking its sha256,
  and points the build at the copy with `go mod edit -replace`. The build fails if the file's hash is
  wrong, if the hunk needs any offset or fuzz, if the patched line is missing, if the replace did not
  take, or if any of the four built libraries does not record the replaced module.

## When sing-box is bumped

The patch must apply to the new sing-tun with no offset and no fuzz, or the build stops — nobody should
re-read a hunk that moved. If upstream's `Attach` already passes `nil` through, delete this patch, this
file, and the Dockerfile steps that apply it, and correct `client-android/NOTICE` and
`docs/LICENSING_v0.1.md`, which say the library is modified.

**Whenever the built libraries change** — a bump, or any change to this patch — regenerate
`client-android/sing-box-libbox/release-libbox.sha256` from the build's own `libbox.sha256`, rewriting
`jni/<abi>/` to `lib/<abi>/`, in the same commit as the new `jniLibs`. `scripts/release-check.sh` reads
that list at the commit it is pinned to, so a release and its list must move together;
`v0.1.0-libbox.sha256` never changes.
