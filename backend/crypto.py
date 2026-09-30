# -*- coding: utf-8 -*-
"""
crypto.py — 静态落盘加密（Encryption at Rest）
================================================
设计目标（对应需求）：
  * 敏感目录下的文件在**离开 NameNode 内存、落盘到 DataNode 之前**先加密，
    DataNode 磁盘上的 blocks/<bid>.dat 是不可直接读懂的密文容器；
    读取时由 NameNode 透明解密，上层（下载/预览/diff/版本）无感。
  * 每个加密目录（scope）维护一条**永不删除的密钥版本链**：
    轮换只追加新版本——块自写入起不可变，旧块头部记录其 kid，
    读时按 kid 取对应版本的密钥。因此：
      - 旧文件（历史提交里的块同理）始终可用旧密钥解密；
      - 轮换完成后写入的新文件使用新当前密钥；
      - 轮换是一次元数据原子切换，不存在"密钥换了、旧块读不出"的窗口；
      - 任何一份历史版本都不会因轮换而失效（旧密钥永久保留）。
  * 完整密钥只在管理员**再次确认口令**后一次性展示，平时只暴露指纹/版本等摘要。

算法说明（教学系统，零第三方依赖）：
  * 流密码：CTR 工作模式，核心 PRF 为 HMAC-SHA256（OpenSSL C 实现，性能足够）。
      密钥流 block_i = HMAC-SHA256(mac_key, ENC || nonce || counter64)，64B/块。
  * 完整性：HMAC-SHA256(tag_key, "DFSVS-TAG-v1" || nonce || kid || ciphertext)。
    此外 DataNode 侧仍对密文容器整体做 sha256 校验（静默损坏/副本一致性沿用原链路）。
  * 每块使用 16 字节随机 nonce；同 kid 下重复概率可忽略。
  * 密钥由 os.urandom(32) 生成；指纹 = sha256(key)[:16]（不可逆，可用于比对）。

密文容器格式（DataNode 磁盘上的实际字节）::

    DFSENC1\n
    {"v":1,"kid":"...","nonce":"<hex32>","tag":"<hex64>","plain_size":N}\n
    \n
    <ciphertext ...>

未启用加密的目录写入的块保持原样（裸明文块），两种格式可共存于同一 DataNode。
"""

import hashlib
import hmac
import json
import os

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------

FORMAT_MAGIC = b"DFSENC1"
HEADER_PROTO = 1
NONCE_BYTES = 16
KEY_BYTES = 32
STREAM_BLOCK = 64          # SHA-256 输出 32B，HMAC 一次产出 32B；按 32B 切块即可

_TAG_INFO = b"DFSVS-TAG-v1"
_ENC_INFO = b"DFSVS-ENC-v1"
_MAC_INFO = b"DFSVS-MAC-v1"


class CryptoError(Exception):
    pass


# ----------------------------------------------------------------------------
# 密钥派生 / 工具
# ----------------------------------------------------------------------------

def generate_key():
    """生成一把 32 字节的数据密钥（CSPRNG）。"""
    return os.urandom(KEY_BYTES)


def key_fingerprint(key):
    """密钥指纹：sha256(key) 前 16 字节十六进制（不可逆，仅用于展示/比对）。"""
    return hashlib.sha256(key).hexdigest()[:32]


def _derive(master, info):
    """从主密钥派生用途子密钥（HKDF-Expand 风格的单步派生）。"""
    return hmac.new(master, info, hashlib.sha256).digest()


def _mac_key(master):
    return _derive(master, _MAC_INFO)


def _tag_key(master):
    return _derive(master, _TAG_INFO)


def _keystream_block(mac_key, nonce, counter):
    """密钥流第 counter 块（32 字节）。"""
    msg = _ENC_INFO + nonce + counter.to_bytes(8, "big")
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def _xor_stream(key, nonce, data):
    """CTR 模式核心：data 与密钥流逐字节异或（加密/解密同一函数）。"""
    mac_key = _mac_key(key)
    out = bytearray()
    counter = 0
    pos = 0
    # 按 32B 密钥流块处理；用大整数异或（C 实现）避免逐字节 Python 循环
    while pos < len(data):
        chunk = data[pos:pos + 32]
        ks = _keystream_block(mac_key, nonce, counter)[:len(chunk)]
        out += (int.from_bytes(chunk, "big")
                ^ int.from_bytes(ks, "big")).to_bytes(len(chunk), "big")
        pos += 32
        counter += 1
    return bytes(out)


def _compute_tag(key, nonce, kid, ciphertext):
    h = hmac.new(_tag_key(key), _TAG_INFO, hashlib.sha256)
    h.update(nonce)
    h.update(kid.encode("utf-8"))
    h.update(ciphertext)
    return h.hexdigest()


# ----------------------------------------------------------------------------
# 封包 / 解包
# ----------------------------------------------------------------------------

def seal_block(plaintext, key, kid):
    """
    明文块 -> 密文容器 bytes（落盘/复制的就是它）。
    kid 由调用方（CryptoManager）给出，标识本块使用的密钥版本。
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError("seal_block 仅接受 bytes")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = _xor_stream(key, nonce, bytes(plaintext))
    tag = _compute_tag(key, nonce, kid, ciphertext)
    header = {
        "v": HEADER_PROTO,
        "kid": kid,
        "nonce": nonce.hex(),
        "tag": tag,
        "plain_size": len(plaintext),
    }
    header_b = json.dumps(header, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    return FORMAT_MAGIC + b"\n" + header_b + b"\n\n" + ciphertext


def is_encrypted_blob(blob):
    """判断 DataNode 上读回的字节是否为密文容器。"""
    return bool(blob) and blob[:len(FORMAT_MAGIC) + 1] == FORMAT_MAGIC + b"\n"


def parse_header(blob):
    """解析容器头部，返回 (header_dict, ciphertext_offset)。"""
    if not is_encrypted_blob(blob):
        raise CryptoError("不是 DFSENC1 密文容器")
    sep = blob.find(b"\n\n", len(FORMAT_MAGIC) + 1)
    if sep < 0:
        raise CryptoError("密文容器头部不完整")
    header_line = blob[len(FORMAT_MAGIC) + 1:sep]
    try:
        header = json.loads(header_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CryptoError("密文容器头部无法解析")
    for field in ("kid", "nonce", "tag"):
        if field not in header:
            raise CryptoError(f"密文容器头部缺少字段: {field}")
    return header, sep + 2


def open_block(blob, key_resolver):
    """
    密文容器 -> 明文 bytes（读取路径使用）。
    key_resolver(kid) -> 该版本密钥 bytes；找不到密钥则抛 CryptoError。
    依次校验：魔数 / HMAC 认证标签 / 明文长度。任何一步失败都拒绝解密。
    """
    header, body_off = parse_header(blob)
    kid = header["kid"]
    key = key_resolver(kid)
    if key is None:
        raise CryptoError(f"密钥版本 {kid} 已不存在，无法解密该块")
    ciphertext = blob[body_off:]
    expected_tag = _compute_tag(key, bytes.fromhex(header["nonce"]), kid,
                                ciphertext)
    if not hmac.compare_digest(expected_tag, header.get("tag", "")):
        raise CryptoError("密文认证标签不匹配（密钥错误或数据被篡改）")
    plaintext = _xor_stream(key, bytes.fromhex(header["nonce"]), ciphertext)
    declared = header.get("plain_size")
    if declared is not None and declared != len(plaintext):
        raise CryptoError("解密后明文长度与头部声明不一致")
    return plaintext, {"kid": kid, "plain_size": len(plaintext)}
