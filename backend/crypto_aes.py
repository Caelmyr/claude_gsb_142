# -*- coding: utf-8 -*-
"""
crypto_aes.py — 纯标准库实现的 AES-256-CTR
============================================
本项目约束「仅 Python 标准库、零第三方依赖」，因此此处提供一份
教学级、恒定轮次的 AES 实现（FIPS-197），配合 NIST SP 800-38A 的
CTR 工作模式用于静态数据加密（encryption-at-rest）：

  * 算法：AES-256（14 轮，32 字节密钥）；
  * 模式：CTR —— 明文/密文按块异或密钥流，长度保持不变，
    且支持从任意字节偏移 seek（Range 读只需把计数器推进对应块数）；
  * IV/nonce：96 位随机 nonce + 32 位块计数器（初始 2），
    由加密方为每块生成 12 字节随机 nonce；
  * 完整性：系统另以「明文 SHA-256 校验和」在读取/巡检路径验真
    （块表 checksum 存明文哈希，on-disk checksum 存密文哈希），
    密文被篡改时解密结果无法通过明文校验和，等价于完整性保护。

安全说明：
  这是可读、可审计的参考实现（表驱动），非恒定时间实现，
  仅用于教学/模拟系统；生产环境请改用 cryptography / openssl。

正确性：模块底部的自测对照 NIST CAVS AES-256 ECB 已知答案与
SP 800-38A CTR 向量（见 _self_test()，import 时不执行，
由 tests / Keyring 初始化时调用一次）。
"""

import os

# ---------------------------------------------------------------------------
# AES S-box / 逆 S-box（FIPS-197 Figure 7/14）
# ---------------------------------------------------------------------------

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

_INV_SBOX = tuple(_SBOX.index(i) for i in range(256))

# 轮常量 Rcon（AES-256 最多需要 7 个，给出 10 个备用）
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a):
    """GF(2^8) 乘 x（左移一位，溢出则异或 0x1b）。"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _gmul(a, b):
    """GF(2^8) 通用乘法（俄罗斯 peasant 算法）。"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


# ---------------------------------------------------------------------------
# AES 核心（128/192/256 位密钥自适应；本系统只用 256）
# ---------------------------------------------------------------------------

class AES:
    """表驱动 AES。用法：AES(key).encrypt_block(block16) / decrypt_block。"""

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES 密钥长度必须为 16/24/32 字节")
        self.nk = len(key) // 4
        self.nr = self.nk + 6          # 10 / 12 / 14 轮
        self.round_keys = self._key_expansion(key)

    def _key_expansion(self, key):
        nk, nr = self.nk, self.nr
        total = 4 * (nr + 1)          # 以 word(4B) 计的轮密钥总量
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, total):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                    # RotWord
                temp = [_SBOX[b] for b in temp]               # SubWord
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        # 展平为逐轮 16 字节
        flat = bytes(b for word in w for b in word)
        return [flat[16 * r:16 * r + 16] for r in range(nr + 1)]

    # ---- 单轮变换（以 16 字节 list 表示状态，列优先） ----
    @staticmethod
    def _add_round_key(state, rk):
        for i in range(16):
            state[i] ^= rk[i]

    @staticmethod
    def _sub_bytes(state, box):
        for i in range(16):
            state[i] = box[state[i]]

    @staticmethod
    def _shift_rows(s):
        # 列优先：s[r + 4c]；行 r 循环左移 r 字节
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

    @staticmethod
    def _inv_shift_rows(s):
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

    @staticmethod
    def _mix_columns(state):
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i:i + 4]
            state[i] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            state[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            state[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            state[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)

    @staticmethod
    def _inv_mix_columns(state):
        for c in range(4):
            i = 4 * c
            a = state[i:i + 4]
            state[i] = _gmul(a[0], 0x0e) ^ _gmul(a[1], 0x0b) \
                ^ _gmul(a[2], 0x0d) ^ _gmul(a[3], 0x09)
            state[i + 1] = _gmul(a[0], 0x09) ^ _gmul(a[1], 0x0e) \
                ^ _gmul(a[2], 0x0b) ^ _gmul(a[3], 0x0d)
            state[i + 2] = _gmul(a[0], 0x0d) ^ _gmul(a[1], 0x09) \
                ^ _gmul(a[2], 0x0e) ^ _gmul(a[3], 0x0b)
            state[i + 3] = _gmul(a[0], 0x0b) ^ _gmul(a[1], 0x0d) \
                ^ _gmul(a[2], 0x09) ^ _gmul(a[3], 0x0e)

    def encrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("AES 块必须为 16 字节")
        state = list(block)
        self._add_round_key(state, self.round_keys[0])
        for r in range(1, self.nr):
            self._sub_bytes(state, _SBOX)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[r])
        self._sub_bytes(state, _SBOX)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.nr])
        return bytes(state)

    def decrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("AES 块必须为 16 字节")
        state = list(block)
        self._add_round_key(state, self.round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._sub_bytes(state, _INV_SBOX)
            self._add_round_key(state, self.round_keys[r])
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._sub_bytes(state, _INV_SBOX)
        self._add_round_key(state, self.round_keys[0])
        return bytes(state)


# ---------------------------------------------------------------------------
# CTR 模式（NIST SP 800-38A 风格：计数器块可定制；本系统用 96bit nonce）
# ---------------------------------------------------------------------------

BLOCK = 16
NONCE_LEN = 12            # 96 位 nonce
COUNTER_INIT = 2          # 32 位计数器初值（与常见库约定一致）


def _counter_block(nonce, counter):
    """96 位 nonce || 32 位大端计数器。"""
    return bytes(nonce) + counter.to_bytes(4, "big")


def _xor_stream(cipher, nonce, counter, nbytes, skip=0):
    """
    生成 nbytes 字节密钥流（可跳过前 skip 字节），用于与数据异或。
    skip 支持 CTR 的随机访问：把计数器推进到 skip//16 即可从任意偏移
    加解密（Range 读路径使用）。
    """
    out = bytearray()
    ctr = counter + skip // BLOCK
    block_offset = skip % BLOCK
    remaining = nbytes
    while remaining > 0:
        ks = cipher.encrypt_block(_counter_block(nonce, ctr))
        if block_offset:
            ks = ks[block_offset:]
            block_offset = 0
        out.extend(ks[:remaining])
        remaining -= len(ks)
        ctr += 1
    return bytes(out)


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def aes_ctr_xor(key, nonce, data, counter=COUNTER_INIT, offset=0):
    """
    CTR 加/解密同一运算：ciphertext = plaintext XOR keystream。
      key     —— 32 字节 AES-256 密钥
      nonce   —— 12 字节随机 nonce
      data    —— 明文或密文
      counter —— 计数器初值
      offset  —— data 对应整段密文中的字节偏移（Range 读时非 0）
    """
    if len(nonce) != NONCE_LEN:
        raise ValueError("CTR nonce 必须为 12 字节")
    cipher = AES(key)
    ks = _xor_stream(cipher, nonce, counter, len(data), skip=offset)
    return _xor_bytes(data, ks)


def new_nonce():
    return os.urandom(NONCE_LEN)


# ---------------------------------------------------------------------------
# 自测：NIST CAVS AES-256-ECB 已知答案 + SP 800-38A AES-256-CTR 向量
# ---------------------------------------------------------------------------

def _self_test():
    # FIPS-197 Appendix C.3 —— AES-256 ECB
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                      "101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct_expected = "8ea2b7ca516745bfeafc49904b496089"
    aes = AES(k)
    assert aes.encrypt_block(pt).hex() == ct_expected, "AES-256 ECB 加密向量失败"
    assert aes.decrypt_block(bytes.fromhex(ct_expected)) == pt, "AES-256 ECB 解密向量失败"

    # NIST SP 800-38A F.5.5 CTR-AES256.Encrypt
    ctr_key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ctr_plain = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    ctr_expected = (
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")
    # SP800-38A 的计数器是全 128 位递增；用其前 12 字节做 nonce、
    # 末 4 字节的大端整数作为 32 位计数器初值
    nonce = iv[:12]
    ctr0 = int.from_bytes(iv[12:16], "big")
    got = aes_ctr_xor(ctr_key, nonce, ctr_plain, counter=ctr0)
    assert got.hex() == ctr_expected, "AES-256 CTR 加密向量失败"
    assert aes_ctr_xor(ctr_key, nonce, got, counter=ctr0) == ctr_plain, \
        "AES-256 CTR 解密向量失败"

    # offset 随机访问：从第 23 字节处做区段 CTR 应与整段结果一致
    full = aes_ctr_xor(ctr_key, nonce, ctr_plain, counter=ctr0)
    seg = aes_ctr_xor(ctr_key, nonce, ctr_plain[23:57], counter=ctr0,
                      offset=23)
    assert seg == full[23:57], "CTR offset seek 失败"
    return True


if __name__ == "__main__":
    _self_test()
    print("AES-256-CTR self-test OK (NIST vectors passed)")
