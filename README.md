# QQ 音乐网络请求签名算法（network signature）

QQ 音乐客户端网络请求的**签名与设备指纹算法** —— 纯 Python 实现，
逆向自客户端 `libmer.so`（MERJni / QqTeaCryptor / EkeyApiClient）。

**只依赖 Python 标准库**，无第三方依赖，不含任何网络请求代码。

## 包含内容

| 部分 | 说明 |
|---|---|
| **TEA-CBC 加密** | `QqTeaCryptor.encrypt()` 的等价实现（QQ 私有变体：IV 用的是"异或后的输入"而非密文） |
| **M-Encoding** | 5 字节随机前缀 + Deflate 压缩 |
| **OpenUDID** | `computeUdID()`：由 Android ID 的 Java `hashCode()` 派生 UUID |
| **M-Value** | `computeMValue()`：JSON → TEA-CBC → base64 |
| **请求签名** | `MERJni.calc()`：<br>`sign = base64( nonce(12B) + HMAC-SHA1(key, reverse(base64(body))) )`<br>`mask = md5(body).hexdigest()`<br>⚠️ **签名密钥不包含在本仓库中，需自行获取（见下）** |

## 用法

```bash
python3 qqmusic_sign.py selftest            # 自检（确定性输出）
python3 qqmusic_sign.py udid  <android_id>  # 算 OpenUDID
python3 qqmusic_sign.py mvalue <android_id> # 算 M-Value
python3 qqmusic_sign.py sign  <body文件>    # 算请求签名 sign + mask
```

作为库使用：

```python
from qqmusic_sign import calc_sign, calc_mask, compute_udid, compute_m_value

sign, mask = calc_sign(raw_body), calc_mask(raw_body)
```

## ⚠️ 关于 HMAC 签名密钥（本仓库不含，需自行获取）

代码中**不包含**用于请求签名的 12 字节 HMAC-SHA1 密钥。

它原本逆向自客户端二进制的 `libmer.so`，属于第三方私有实现的一部分，出于合规考虑
**本仓库不公开该密钥** —— 文件顶部只保留一个空变量：

```python
HMAC_KEY = bytes.fromhex("")   # ← 请自行填入
```

请自行分析客户端获取该密钥，或替换为你自己的等价实现。未填入时：

| 功能 | 状态 |
|---|---|
| TEA-CBC 加密 / M-Encoding / OpenUDID / M-Value | ✅ 照常可用 |
| `mask` 计算（MD5） | ✅ 照常可用 |
| `calc_sign()` / `sign` 子命令 | ❌ 抛出 `RuntimeError` 提示需填入密钥 |
| 自检中的 sign 检查项 | ⏭️ 显示 `SKIP` |

填入方式（任选其一）：

```bash
# 方式一：直接改文件顶部
HMAC_KEY = bytes.fromhex("你的 12 字节密钥的 hex")

# 方式二：从环境变量读取
import os
HMAC_KEY = bytes.fromhex(os.environ.get("QQMUSIC_HMAC_KEY", ""))
```

## 自检结果

```
PASS compute_udid 返回 32 位 hex
PASS compute_m_value 输出 base64 (108 字符)
PASS mask = md5 hex 32 字符
SKIP sign 相关检查 —— HMAC_KEY 未设置（需自行填入，见上）
PASS TEA-CBC 输出为 8 的倍数 (24)
```

> 填入自己的 HMAC_KEY 后，`SKIP` 的检查项会变为 `PASS`。

## 免责声明

本项目仅用于**安全研究与协议学习**。其中的常量（HMAC 密钥、TEA 常量）来自对客户端
二进制的逆向分析，属于第三方协议的实现细节。请勿用于破解付费内容、绕过版权保护或
任何商业用途；由此产生的一切后果由使用者自负。
