# VAYDNS Fast UDP (KCP) - new, separate speed-boost option

This adds a NEW, opt-in option alongside your existing, untouched VAYDNSTT BOOSTER.
Nothing about the current booster's behavior changes unless you turn the new
toggle on for a given server/profile.

## What it is
Your server already runs `vaydns-server` (net2share/vaydns), but your panel has
always forced it into `-dnstt-compat` (legacy dnstt wire format) because the app
had no client that could speak VayDNS's own, much faster protocol (KCP/smux
reliable UDP, no DNS-query round trips). That's the real reason the other app
hits ~5MB/s on "Slow DNSTT" while yours tops out around 800kb/s with boosters -
it's not a tuning difference, it's a different wire protocol.

This change adds a real `vaydns-client` to the app (arm64-v8a only - see
Limitations) as a brand-new "VAYDNS FAST UDP (KCP)" toggle, and a matching
"Fast UDP" prompt on your server panel so you can set up an instance that
actually speaks that faster protocol.

## Files in this delivery
- `speedmaxpro_vaydns_fastudp_client.zip` - the 5 changed/added Android files:
  - `java/org/utralmode/tunnel/VayDnsFastClone.java` (NEW) - runs the real vaydns-client binary
  - `java/org/utralmode/tunnel/TunnelManagerThread.java` - adds a new, separate dispatch
    branch + `VaydnsttFast()` method; your existing `Vaydnstt()` booster method is unchanged
  - `java/org/utralmode/config/Settings.java` - adds `vayFastUdp()`/`setVayFastUdp()`
  - `java/org/utralmode/config/SettingsConstants.java` - adds the new preference key
  - `res/xml/advanced_settings_preference.xml` - adds the "VAYDNS FAST UDP (KCP)" checkbox
    (only enabled once VAYDNSTT BOOSTER itself is on)
- `libvaydns_arm64.so` - the real, unmodified upstream vaydns-client, compiled for arm64-v8a
  Android. **Place this at**: `app/src/main/jniLibs/arm64-v8a/libvaydns.so` in your Android
  Studio project (create the `arm64-v8a` folder if it doesn't exist).
- `dnstt_manager.py` - your server panel script with the server-side change applied
  (also provided as `dnstt_manager_vaydns_fastudp.patch` if you'd rather apply it yourself
  with `git apply` / `patch`).

## How to use it
1. **Server side**: In your panel's routed/booster "ADD NEW INSTANCE" flow, add a NEW
   vaydns instance (don't touch your existing one) and when asked, choose
   "Fast UDP - KCP" instead of "Legacy / Compatible". Note its domain, pubkey and server IP.
2. **Client side (Android Studio)**:
   - Apply the 5 files from the zip over your project (same relative paths).
   - Drop `libvaydns.so` into `app/src/main/jniLibs/arm64-v8a/`.
   - Rebuild and install.
3. **In the app**: create/point a connection profile's server/domain/pubkey fields at the
   NEW Fast UDP server instance (not your old one), then in Advanced Settings turn on
   both "VAYDNSTT BOOSTER" and the new "VAYDNS FAST UDP (KCP)" checkbox underneath it.
   Connect as normal.

## Limitations (please read)
- **arm64-v8a only for now.** This sandbox can cross-compile pure-Go Android binaries
  without the NDK, but only for `android/arm64` - the 32-bit/x86 targets need the NDK's
  C toolchain for cgo linking, and the NDK download is blocked from here. If any of your
  users are on 32-bit-only devices, Fast UDP simply won't be available to them (the app
  will say the binary is missing for their device and they should keep using the regular
  booster) - everyone else is unaffected.
- This only works against a Fast UDP server instance. Pointing a Fast-UDP-enabled
  profile at your OLD (legacy/compat) server instance will fail to connect - that's
  expected; the two are different wire protocols on purpose.
- A single Fast UDP connection is used (not multiplied across several paths like the
  regular booster) - the speed gain comes from the protocol itself being far more
  efficient, not from parallelism, so this is intentional, not a missing feature. If you
  want it combined with multiple parallel paths too, that's a reasonable next step but
  wasn't part of what's described above.

## Status of the OTHER open item (speed ticker)
Still unresolved, independent of this. Whenever you get a chance to reconnect on a
non-Slow-DNSTT protocol with this build, please grab the `[SpeedTicker]` lines from the
Log Viewer (they log every second now) and send them over - that's what's needed to
finally pin down the real cause.
