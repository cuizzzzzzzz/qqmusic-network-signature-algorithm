**English** · [简体中文](README.zh-CN.md)

# QQ Music Android Client — Request Signature

> ### 📱 This is the **mobile (Android client)** implementation
> Derived from the Android app's **`libmer.so` (MERJni)**: TEA-CBC encryption, device fingerprinting
> (OpenUDID / M-Value) and request signing (HMAC-SHA1).
>
> ⚠️ **How this differs from other public QQ Music signing projects**: most public projects target the
> **web / PC client** (web endpoint `sign` computation, PC-client `musicu.fcg` signing). This project
> covers the **mobile app's** signing chain — parameter names (`authst` / `wxrefresh_token` /
> `tmeLoginType` …), device fingerprint and keys are **all different**.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib_only-success)
![Platform](https://img.shields.io/badge/target-Android%20%2F%20ARM64-orange)
![Key](https://img.shields.io/badge/HMAC%20key-not%20included-critical)

---

## What this is

The QQ Music Android client signs every private-API request and attaches device fingerprints:

| Part | Client implementation | Function here |
|---|---|---|
| TEA-CBC encryption | `QqTeaCryptor.encrypt()` | `tea_cbc_encrypt()` |
| M-Encoding | 5 random bytes + Deflate | `m_encode_body()` |
| Device OpenUDID | `EkeyApiClient.computeUdID()` | `compute_udid()` |
| M-Value | `EkeyApiClient.computeMValue()` | `compute_m_value()` |
| Request signature | `MERJni.calc()` | `calc_sign()` / `calc_mask()` |

**Mobile-specific quirk**: the TEA-CBC chaining IV is the *XOR-ed **input** block* rather than the
standard CBC ciphertext block; the first block is XOR-ed with an all-zero IV, and the output is XOR-ed
once more.

## ⚠️ About the HMAC signing key (not included — bring your own)

This repository does **not** contain the 12-byte HMAC-SHA1 key used for request signing. It was
originally extracted from `libmer.so`, which is part of a third-party private implementation, so it is
**deliberately not published** here. The file keeps an empty placeholder:

```python
# top of qqmusic_sign.py
HMAC_KEY = ...   # ← put your own 12-byte key (hex string) here
```

Without it:

| Feature | State |
|---|---|
| TEA-CBC / M-Encoding / OpenUDID / M-Value | ✅ works |
| `mask` (MD5) | ✅ works |
| `calc_sign()` / `sign` subcommand | ❌ raises `RuntimeError` asking for the key |
| sign-related self-tests | ⏭️ reported as `SKIP` |

## Usage

```bash
git clone https://github.com/cuizzzzzzzz/qqmusic-network-signature-algorithm.git
cd qqmusic-network-signature-algorithm

python3 qqmusic_sign.py selftest               # self-test (deterministic)
python3 qqmusic_sign.py udid  <android_id>     # compute OpenUDID
python3 qqmusic_sign.py mvalue <android_id>    # compute M-Value
python3 qqmusic_sign.py sign  <body-file>      # compute sign + mask (needs your HMAC_KEY)
```

As a library:

```python
from qqmusic_sign import calc_sign, calc_mask, compute_udid, compute_m_value

sign, mask = calc_sign(raw_body), calc_mask(raw_body)
```

**Requirements**: Python 3.8+, **no third-party dependencies**.

## Self-test

```
$ python3 qqmusic_sign.py selftest
PASS compute_udid returns 32-char hex
PASS compute_m_value returns base64 (108 chars)
PASS mask = md5 hex, 32 chars
SKIP sign checks — HMAC_KEY not set (bring your own)
PASS TEA-CBC output is a multiple of 8 (24)

self-test: all passed
```

> Once you fill in your own HMAC_KEY, the `SKIP` checks turn into `PASS`.

## Keywords

`QQMusic signature` `signature algorithm` `Android reverse engineering` `libmer.so` `meri JNI`
`TEA` `TEA-CBC` `OpenUDID` `M-Value` `device fingerprint` `HMAC-SHA1` `request signing`
`Tencent Music` `TME` `mobile client` `QQ音乐签名`

## Related projects

- **[qqmusic-music-decrypt-algorithm](https://github.com/cuizzzzzzzz/qqmusic-music-decrypt-algorithm)**
  — encrypted audio decryption of the same Android client (QMC / ekey / segmented RC4 keystream)

## Disclaimer

This project is for **security research and protocol study only**. Do not use it to break paid
content, bypass copyright protection, or for any commercial purpose. It contains **no network code**
and **no keys**. Use at your own risk.
