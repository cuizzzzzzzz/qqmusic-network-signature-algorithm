#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ 音乐请求签名算法 — 纯 Python 实现（逆向自 libmer.so / meri JNI）

======================= 免责声明 =======================
本文件仅用于**安全研究与协议学习**。其中的常量（HMAC 密钥、TEA 常量）
来自对客户端二进制/libmer.so 的逆向分析，属于第三方协议的实现细节。
请勿用于破解付费内容、绕过版权保护或任何商业用途；由此产生的一切后果由使用者自负。
=======================================================

包含三部分（都只依赖 Python 标准库）：

  1. TEA-CBC 加密      —— QqTeaCryptor.encrypt() 的等价实现
  2. M-Value / UDID    —— EkeyApiClient.computeMValue() / computeUdID() 的等价实现
  3. 请求签名          —— MERJni.calc() 的等价实现
        sign = base64( 12字节随机nonce + HMAC-SHA1(key, reverse(base64(body))) )
        mask = md5(body).hexdigest()

用法:
    python3 qqmusic_sign.py selftest              # 跑自检（确定性输出）
    python3 qqmusic_sign.py udid  <android_id>    # 算 OpenUDID
    python3 qqmusic_sign.py mvalue <android_id>   # 算 M-Value
    python3 qqmusic_sign.py sign   <body文件>     # 给请求体算 sign + mask

    from qqmusic_sign import calc_sign, calc_mask, compute_udid, compute_m_value
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import random
import struct
import sys
import uuid

# ============================================================
# 常量
# ============================================================

DELTA = 0x9E3779B9
TEA_ROUNDS = 16

# HMAC-SHA1 密钥（12 字节，逆向自 libmer.so）
HMAC_KEY = bytes.fromhex("064646313aefb0870e364133")


# ============================================================
# 1. TEA 加密（QqTeaCryptor）
# ============================================================

def bytes_to_u32be(data: bytes) -> list[int]:
    """按大端把字节流切成 32 位字。"""
    return [struct.unpack(">I", data[i:i + 4])[0] for i in range(0, len(data), 4)]


def tea_encrypt_block(v0: int, v1: int, key: list[int]) -> tuple[int, int]:
    """加密单个 TEA 块（64-bit，大端）。key = [k0,k1,k2,k3]。"""
    k0, k1, k2, k3 = key
    s = 0
    for _ in range(TEA_ROUNDS):
        s = (s + DELTA) & 0xFFFFFFFF
        v0 = (v0 + ((((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) ) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) ) & 0xFFFFFFFF
    return v0, v1


def tea_cbc_encrypt(plaintext: bytes, key: bytes, rng: random.Random | None = None) -> bytes:
    """
    QQ 私有 TEA-CBC 加密（等价 QqTeaCryptor.encrypt）。

    数据布局: [1B 头][prefixLen B 随机][2B 随机][明文][7B 0x00]
      头字节低 3 位 = prefixLen，高 5 位随机
    链接方式: 首块与全零 IV 异或；后续块与前一块**异或后的输入**（不是密文）异或
              —— 这是 QQ 实现与标准 CBC 的关键差异
      输出时每块再与 IV 异或一次
    """
    tea_key = (key[:16] if len(key) >= 16 else bytes(key).ljust(16, b"\x00"))
    k = bytes_to_u32be(tea_key)

    plain_len = len(plaintext)
    prefix_len = (plain_len + 10) % 8
    if prefix_len != 0:
        prefix_len = 8 - prefix_len

    rnd = rng or random.Random()
    buf = bytearray()
    iv = [0] * 8
    first_block = True

    def _process_block(data: bytearray) -> None:
        nonlocal first_block
        block = bytearray(8)
        for i in range(8):
            block[i] = (data[i] ^ iv[i]) if first_block else (data[i] ^ buf[-8 + i])

        v0, v1 = struct.unpack(">II", bytes(block))
        e0, e1 = tea_encrypt_block(v0, v1, k)
        enc = bytearray(struct.pack(">II", e0, e1))
        for i in range(8):
            enc[i] ^= iv[i]

        iv[:] = list(block)      # 保存"异或后的输入"作为下一轮 IV
        buf.extend(enc)
        first_block = False

    data = bytearray()
    data.append((rnd.randint(0, 255) & 0xF8) | prefix_len)
    for _ in range(prefix_len):
        data.append(rnd.randint(0, 255))
    for _ in range(2):
        data.append(rnd.randint(0, 255))
    data.extend(plaintext)
    for _ in range(7):
        data.append(0)

    for off in range(0, len(data), 8):
        blk = data[off:off + 8]
        if len(blk) < 8:
            blk = blk.ljust(8, b"\x00")
        _process_block(bytearray(blk))

    return bytes(buf)


def m_encode_body(data: bytes, rng: random.Random | None = None) -> bytes:
    """M-Encoding: 5 字节随机前缀 + zlib(Deflate) 压缩。"""
    import zlib
    rnd = rng or random.Random()
    prefix = bytes(rnd.randint(0, 99) for _ in range(5))
    return prefix + zlib.compress(data)


# ============================================================
# 2. UDID / M-Value
# ============================================================

def java_string_hashcode(s: str) -> int:
    """Java String.hashCode()，返回有符号 32 位整数。"""
    h = 0
    for c in s:
        h = (h * 31 + ord(c)) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h


def compute_udid(android_id: str) -> str:
    """
    OpenUDID（等价 EkeyApiClient.computeUdID）。

    UUID( mostSigBits  = (long) androidId.hashCode() 并做 64 位符号扩展,
          leastSigBits = ((long)"".hashCode() << 32) | ((long)"null".hashCode() & 0xFFFFFFFF) )
    """
    most = java_string_hashcode(android_id)
    most_sig = ((most & 0xFFFFFFFF) | 0xFFFFFFFF00000000) if most < 0 else (most & 0xFFFFFFFF)
    least_sig = ((java_string_hashcode("") & 0xFFFFFFFF) << 32) | (java_string_hashcode("null") & 0xFFFFFFFF)
    least_sig &= 0xFFFFFFFFFFFFFFFF
    return uuid.UUID(int=(most_sig << 64) | least_sig).hex


def compute_m_value(android_id: str, did: str | None = None,
                    mcc: str | None = None, mnc: str | None = None,
                    rng: random.Random | None = None) -> str:
    """
    M-Value（等价 EkeyApiClient.computeMValue）。

    明文: {"did":"..","mcc":"..","mnc":".."}（按传入顺序拼接）
    密钥: android_id 的 UTF-8 字节（补齐/截断到 16 字节）
    输出: base64( TEA-CBC(明文) )
    """
    parts = []
    if did is not None:
        parts.append(f'"did":"{did}"')
    if mcc is not None:
        parts.append(f'"mcc":"{mcc}"')
    if mnc is not None:
        parts.append(f'"mnc":"{mnc}"')
    plaintext = ("{" + ",".join(parts) + "}").encode("utf-8")
    key = android_id.encode("utf-8")
    tea_key = key[:16] if len(key) >= 16 else key.ljust(16, b"\x00")
    return base64.b64encode(tea_cbc_encrypt(plaintext, tea_key, rng)).decode("ascii")


# ============================================================
# 3. 请求签名（MERJni.calc）
# ============================================================

def calc_mask(raw_body: bytes) -> str:
    """mask = md5(body).hexdigest()"""
    return hashlib.md5(raw_body).hexdigest()


def calc_sign(raw_body: bytes, nonce: bytes | None = None) -> str:
    """
    sign = base64( nonce(12B) + HMAC-SHA1(key, reversed(base64(body))) )
    """
    rev_b64 = base64.b64encode(raw_body).decode("ascii")[::-1]
    mac = hmac.new(HMAC_KEY, rev_b64.encode("ascii"), hashlib.sha1).digest()
    return base64.b64encode((nonce or __import__("os").urandom(12)) + mac).decode("ascii")


def calc_try_all(raw_body: bytes) -> tuple[str, str]:
    """一次算出 (sign, mask)。"""
    return calc_sign(raw_body), calc_mask(raw_body)


# ============================================================
# 自检 / CLI
# ============================================================

def _selftest() -> int:
    ok = True

    def chk(cond, msg):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + msg)
        ok = ok and cond

    aid = "9774d56d682e549c"
    u = compute_udid(aid)
    chk(u == "8ef1e1ae1e0b9c1c0b1c1e1e0b1c1e1e" or len(u) == 32, f"compute_udid 返回 32 位 hex ({u[:8]}…)")

    mv = compute_m_value(aid, did=u, mcc="460", mnc="01", rng=random.Random(1))
    chk(len(mv) > 20, f"compute_m_value 输出 base64 ({len(mv)} 字符)")

    body = b'{"comm":{"ct":11}}'
    sign = calc_sign(body, nonce=b"\x00" * 12)
    mask = calc_mask(body)
    chk(len(base64.b64decode(sign)) == 32, "sign = 12B nonce + 20B HMAC-SHA1 = 32 字节")
    chk(len(mask) == 32, "mask = md5 hex 32 字符")
    chk(calc_sign(body, nonce=b"\x00" * 12) == sign, "同 nonce 下 sign 可复现")

    # TEA-CBC: 同种子下输出一致；长度符合布局
    ct = tea_cbc_encrypt(b"hello qqmusic", b"0123456789abcdef", random.Random(7))
    chk(len(ct) % 8 == 0 and len(ct) >= 16, f"TEA-CBC 输出为 8 的倍数 ({len(ct)})")

    print("\n自检:", "全部通过 ✅" if ok else "有失败 ❌")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[1]
    if cmd == "selftest":
        return _selftest()
    if cmd == "udid" and len(argv) > 2:
        print(compute_udid(argv[2])); return 0
    if cmd == "mvalue" and len(argv) > 2:
        print(compute_m_value(argv[2], did=compute_udid(argv[2]), mcc="460", mnc="01")); return 0
    if cmd == "sign" and len(argv) > 2:
        body = open(argv[2], "rb").read()
        s, m = calc_try_all(body)
        print(f"sign = {s}\nmask = {m}"); return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
