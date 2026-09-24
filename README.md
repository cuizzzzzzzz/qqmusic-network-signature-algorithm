# QQ 音乐 安卓客户端 网络签名算法 · QQMusic Android Client Signature

> ### 📱 这是**手机端（Android 客户端）**的逆向实现
> 逆向自 Android App 的 **`libmer.so`（MERJni）**，包含 TEA-CBC 加密、设备指纹（OpenUDID / M-Value）
> 与请求签名（HMAC-SHA1）。
>
> ⚠️ **与网上其他 QQ 音乐签名项目的区别**：公开项目**绝大多数是 Web / PC 端**（网页版接口的
> `sign` 计算、PC 客户端的 `musicu.fcg` 请求签名）。本项目是**移动端 App** 的签名链路，
> 参数名（`authst` / `wxrefresh_token` / `tmeLoginType`…）、设备指纹与密钥**都不同**。

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib_only-success)
![Platform](https://img.shields.io/badge/target-Android%20%2F%20ARM64-orange)
![Key](https://img.shields.io/badge/HMAC%20key-not%20included-critical)

---

## 这是什么

QQ 音乐安卓客户端在调用其私有接口时，会对请求体做一套签名与设备指纹处理：

| 部分 | 客户端实现 | 本仓库函数 |
|---|---|---|
| TEA-CBC 加密 | `QqTeaCryptor.encrypt()` | `tea_cbc_encrypt()` |
| M-Encoding | 5 字节随机前缀 + Deflate | `m_encode_body()` |
| 设备 OpenUDID | `EkeyApiClient.computeUdID()` | `compute_udid()` |
| M-Value | `EkeyApiClient.computeMValue()` | `compute_m_value()` |
| 请求签名 | `MERJni.calc()` | `calc_sign()` / `calc_mask()` |

**移动端特征**：TEA-CBC 用的是 QQ 的**私有变体**——链接时用的 IV 是"异或后的**输入块**"而不是
标准 CBC 的密文块；首块与全零 IV 异或，输出时再异或一次。

## ⚠️ 关于 HMAC 签名密钥（本仓库不含，需自行获取）

代码中**不包含**用于请求签名的 12 字节 HMAC-SHA1 密钥。它原本逆向自 `libmer.so`，属于第三方
私有实现的一部分，出于合规考虑**本仓库不公开该密钥** —— 文件顶部只保留一个空变量：

```python
HMAC_KEY = bytes.fromhex("")   # ← 请自行填入
```

填入方式（任选其一）：

```python
# 方式一：直接改文件顶部
HMAC_KEY = bytes.fromhex("你的 12 字节密钥的 hex")

# 方式二：从环境变量读取
HMAC_KEY = bytes.fromhex(os.environ.get("QQMUSIC_HMAC_KEY", ""))
```

未填入时：

| 功能 | 状态 |
|---|---|
| TEA-CBC 加密 / M-Encoding / OpenUDID / M-Value | ✅ 照常可用 |
| `mask` 计算（MD5） | ✅ 照常可用 |
| `calc_sign()` / `sign` 子命令 | ❌ 抛出 `RuntimeError` 提示需填入密钥 |
| 自检中的 sign 检查项 | ⏭️ 显示 `SKIP` |

## 用法

```bash
git clone https://github.com/cuizzzzzzzz/qqmusic-network-signature-algorithm.git
cd qqmusic-network-signature-algorithm

python3 qqmusic_sign.py selftest               # 自检（确定性输出）
python3 qqmusic_sign.py udid  <android_id>     # 算 OpenUDID
python3 qqmusic_sign.py mvalue <android_id>    # 算 M-Value
python3 qqmusic_sign.py sign  <body文件>       # 算请求签名 sign + mask（需自备 HMAC_KEY）
```

作为库调用：

```python
from qqmusic_sign import calc_sign, calc_mask, compute_udid, compute_m_value

sign, mask = calc_sign(raw_body), calc_mask(raw_body)
```

**环境要求**：Python 3.8+，**无第三方依赖**。

## 自检结果

```
$ python3 qqmusic_sign.py selftest
PASS compute_udid 返回 32 位 hex
PASS compute_m_value 输出 base64 (108 字符)
PASS mask = md5 hex 32 字符
SKIP sign 相关检查 —— HMAC_KEY 未设置（需自行填入）
PASS TEA-CBC 输出为 8 的倍数 (24)

自检: 全部通过 ✅
```

> 填入自己的 HMAC_KEY 后，`SKIP` 的检查项会变为 `PASS`。

## 关键词 / Keywords

`QQ音乐签名` `签名算法` `安卓客户端` `移动端逆向` `libmer` `TEA` `TEA-CBC` `OpenUDID` `M-Value`
`设备指纹` `HMAC-SHA1` `请求签名`
`QQMusic signature` `Android reverse engineering` `libmer.so` `TEA encryption` `OpenUDID`
`device fingerprint` `HMAC-SHA1 sign` `Tencent Music` `TME` `meri JNI`

## 相关项目

- **[qqmusic-music-dectypt-algorithm](https://github.com/cuizzzzzzzz/qqmusic-music-dectypt-algorithm)**
  —— 同一个安卓客户端的**加密音频文件解密**（QMC / ekey / RC4 变体密钥流）

## 免责声明

本项目仅用于**安全研究与协议学习**。请勿用于破解付费内容、绕过版权保护或任何商业用途。
本项目不含任何网络请求代码，也不提供任何密钥。因使用本项目产生的一切后果由使用者自负。
