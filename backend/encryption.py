# -*- coding: utf-8 -*-
"""
encryption.py — 静态数据加密：密钥环（Keyring）/ 目录策略 / 透明加解密
========================================================================
设计目标（对应需求）：
  1. 敏感目录的文件「落盘前加密」：DataNode 磁盘上只有密文，
     直接打开 .dat / 分片暂存均不可读；读取时在 NameNode 透明解密。
  2. 按目录标记：目录策略保存在 meta['encryption'] 文档，
     页面前端展示哪些目录启用了加密、密钥简要信息与轮换入口。
  3. 密钥轮换「无读不出窗口、历史版本永不失效」：
       * 轮换 = 生成新 DEK 作为 active；旧 DEK 原样保留（仅退役，不删除）；
       * 旧块在块表里记录 key_id，读取时按 key_id 取旧 DEK 解密——
         轮换发生在新文件的写入选择上，是一次元数据原子翻转，
         没有任何"旧密钥已删/新密钥未就绪"的中间态；
       * 新文件一律用 active 新密钥；旧文件继续用各自块上记录的旧密钥。
  4. 查看密钥不向无关用户暴露完整明文：
       * DEK 不以明文进入任何普通 API（列表只给指纹/首尾 4 字符等摘要）；
       * 主密钥（KEK）永远不离开 NameNode 本机文件 data/keys/master.key；
       * 完整 DEK 仅 admin 在二次确认（重新校验口令）后经
         /api/encryption/keys/<id>/reveal 一次性获取并审计留痕。

加密原语：AES-256-CTR（backend/crypto_aes.py，NIST 向量自测通过）。
每个数据块独立生成 12 字节随机 nonce；同明文块因 nonce 不同密文不同，
天然禁用密文侧去重；块表保留明文 checksum（读路径验真/完整性），
DN 侧 on-disk checksum 为密文哈希（副本对账/巡检/损坏演练照常工作）。

密钥环文档 meta['encryption'] 结构：
{
  "keyring": {
     "active_id": "kr_...",
     "keys": {
        "<key_id>": {
          "id", "alg": "AES-256-CTR", "version": 1, "state": active|retired,
          "wrapped": "<base64 AESKeyWrapWithHMAC(KEK, DEK)>",
          "fingerprint": "sha256(DEK)[:16]", "created_at", "rotated_at",
          "created_by", "note"
        }
     }
  },
  "policies": [
     {"id":"ep_...", "path":"/finance", "enabled": true,
      "key_id": "<创建时的 active>", "created_at", "created_by", "note": ""}
  ]
}
主密钥文件（不入库、不下发）：
  data/keys/master.key  —— 32 字节随机，0600 权限；
  data/keys/master.key.meta.json —— 指纹/创建信息（不含密钥）。
"""

import base64
import hashlib
import hmac
import os
import stat
import threading

from . import config
from .crypto_aes import AES, aes_ctr_xor, new_nonce
from .util import (atomic_write_json, b64d, b64e, gen_id, norm_path, now,
                   read_json, sha256_bytes)


class EncryptionError(Exception):
    pass


# ============================================================================
# 密钥包装（envelope encryption）
# ----------------------------------------------------------------------------
# 不使用 RFC 3394 的填充约定，采用更直观的「CTR 加密 + HMAC 防伪」封装：
#   wrapped = b64( version(1B) | hmac_sha256(KEK, iv||ct)[:32] | iv(12B) | ct )
# 解包先恒定时间比对 HMAC，再解密；篡改/换 KEK 都会失败。
# ============================================================================

_WRAP_VERSION = b"\x01"
_HMAC_TAG_LEN = 32
_WRAP_IV_LEN = 12


def wrap_dek(kek, dek):
    iv = new_nonce()
    ct = aes_ctr_xor(kek, iv, dek)
    tag = hmac.new(kek, iv + ct, hashlib.sha256).digest()
    return b64e(_WRAP_VERSION + tag + iv + ct)


def unwrap_dek(kek, wrapped):
    try:
        raw = b64d(wrapped)
    except Exception:
        raise EncryptionError("密钥封装不是合法 base64")
    if len(raw) < 1 + _HMAC_TAG_LEN + _WRAP_IV_LEN or raw[:1] != _WRAP_VERSION:
        raise EncryptionError("密钥封装格式不受支持")
    tag = raw[1:1 + _HMAC_TAG_LEN]
    iv = raw[1 + _HMAC_TAG_LEN:1 + _HMAC_TAG_LEN + _WRAP_IV_LEN]
    ct = raw[1 + _HMAC_TAG_LEN + _WRAP_IV_LEN:]
    expect = hmac.new(kek, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise EncryptionError("密钥封装校验失败（主密钥不匹配或封装被篡改）")
    dek = aes_ctr_xor(kek, iv, ct)
    if len(dek) != 32:
        raise EncryptionError("解包出的 DEK 长度非法")
    return dek


def key_fingerprint(dek):
    """DEK 指纹：sha256(DEK) 前 16 hex（展示用，不泄露密钥）。"""
    return sha256_bytes(dek)[:16]


def key_brief(dek, head=4, tail=4):
    """密钥简要：仅首/尾少量字符 + 掩码，用于页面摘要展示。"""
    hx = dek.hex()
    if len(hx) <= head + tail:
        return "•" * 8
    return f"{hx[:head]}{'•' * 16}{hx[-tail:]}"


def generate_dek():
    return os.urandom(32)


# ============================================================================
# 主密钥（KEK）本地文件管理
# ============================================================================

class MasterKeyStore:
    """
    主密钥存放于 NameNode 本机 data/keys/master.key（0600）。
    它只用于包装/解包 DEK，绝不通过网络/API 发送，也不写入任何 JSON 元数据。
    进程内持有明文，落盘仅这一个受权限保护的文件。
    """

    def __init__(self, keys_dir=None):
        self.keys_dir = keys_dir or os.path.join(config.DATA_DIR, "keys")
        self.key_path = os.path.join(self.keys_dir, "master.key")
        self.meta_path = os.path.join(self.keys_dir, "master.key.meta.json")
        self._kek = None
        self._lock = threading.Lock()

    def load_or_create(self):
        with self._lock:
            os.makedirs(self.keys_dir, exist_ok=True)
            if os.path.exists(self.key_path):
                with open(self.key_path, "rb") as f:
                    kek = f.read()
                if len(kek) != 32:
                    raise EncryptionError("主密钥文件长度非法（应为 32 字节）")
                self._kek = kek
            else:
                kek = os.urandom(32)
                fd = os.open(self.key_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(kek)
                        f.flush()
                        os.fsync(f.fileno())
                except BaseException:
                    try:
                        os.unlink(self.key_path)
                    except OSError:
                        pass
                    raise
                os.chmod(self.key_path, 0o600)
                atomic_write_json(self.meta_path, {
                    "alg": "AES-256", "created_at": now(),
                    "fingerprint": key_fingerprint(kek),
                    "note": "NameNode 本地主密钥（KEK），仅用于解包 DEK，"
                            "永不下发/不进 API",
                })
                self._kek = kek
            return self._kek

    @property
    def kek(self):
        if self._kek is None:
            return self.load_or_create()
        return self._kek

    def fingerprint(self):
        return key_fingerprint(self.kek)


# ============================================================================
# 密钥环 + 目录策略
# ============================================================================

class EncryptionManager:
    """
    挂在 NameNode 上：
        nn.crypto = EncryptionManager(nn.meta)
    线程模型：与元数据一致，复用 meta.lock 保护读改写；
    解包后的 DEK 在进程内 LRU 式缓存（key_id -> bytes），缓存不序列化。
    """

    ALG = "AES-256-CTR"

    def __init__(self, meta, master_store=None):
        self.meta = meta
        self.master = master_store or MasterKeyStore()
        self._dek_cache = {}
        self._cache_lock = threading.Lock()

    # ---------------------------------------------------------------- 初始化
    def ensure_seed(self):
        """首次启动：确保 KEK 就绪 + 存在一个 active DEK。"""
        self.master.load_or_create()
        with self.meta.lock:
            doc = self.meta.get("encryption")
            doc.setdefault("keyring", {"active_id": None, "keys": {}})
            doc.setdefault("policies", [])
            kr = doc["keyring"]
            need_new = (not kr.get("active_id")
                        or kr["active_id"] not in kr.get("keys", {}))
            if need_new:
                rec = self._build_key_record(generate_dek(), state="active",
                                             actor="system",
                                             note="初始数据加密密钥")
                kr["keys"][rec["id"]] = rec
                kr["active_id"] = rec["id"]
                self.meta.touch("encryption")

    def _doc(self):
        return self.meta.get("encryption")

    def _keyring(self):
        return self._doc().setdefault("keyring",
                                      {"active_id": None, "keys": {}})

    def _build_key_record(self, dek, state="active", actor="admin", note=""):
        return {
            "id": gen_id("kr"),
            "alg": self.ALG,
            "version": 1,
            "state": state,                      # active | retired
            "wrapped": wrap_dek(self.master.kek, dek),
            "fingerprint": key_fingerprint(dek),
            "brief": key_brief(dek),
            "created_at": now(),
            "rotated_at": None,
            "created_by": actor,
            "note": note or "",
        }

    # ---------------------------------------------------------------- 策略
    @staticmethod
    def _norm(path):
        path = norm_path(path)
        if path == "/":
            raise EncryptionError("不建议对根目录启用加密（请选择具体目录）")
        return path

    def list_policies(self):
        with self.meta.lock:
            return [dict(p) for p in self._doc().get("policies", [])]

    def set_policy(self, path, enabled=True, actor="admin", note=""):
        """
        启用/停用某目录的加密（幂等）。
        启用时记录当时的 active key_id（仅展示用；实际密钥以块表为准）。
        目录必须已存在（避免给拼错的路径静默挂策略）。
        """
        path = self._norm(path)
        with self.meta.lock:
            policies = self._doc().setdefault("policies", [])
            found = next((p for p in policies if p["path"] == path), None)
            if found:
                found["enabled"] = bool(enabled)
                found["updated_at"] = now()
                found["updated_by"] = actor
                if note:
                    found["note"] = note
                if enabled:
                    found["key_id"] = self.active_key_id()
                rec = dict(found)
            else:
                if not enabled:
                    raise EncryptionError("该目录本就未启用加密")
                rec = {
                    "id": gen_id("ep"),
                    "path": path,
                    "enabled": True,
                    "key_id": self.active_key_id(),
                    "created_at": now(),
                    "created_by": actor,
                    "updated_at": now(),
                    "updated_by": actor,
                    "note": note or "",
                }
                policies.append(rec)
            policies.sort(key=lambda p: (-len(p["path"]), p["path"]))
            self.meta.touch("encryption")
            return rec

    def remove_policy(self, path, actor="admin"):
        path = self._norm(path)
        with self.meta.lock:
            policies = self._doc().setdefault("policies", [])
            before = len(policies)
            self._doc()["policies"] = [p for p in policies if p["path"] != path]
            if len(self._doc()["policies"]) == before:
                raise EncryptionError("该目录没有加密策略")
            self.meta.touch("encryption")

    def is_encrypted_path(self, path):
        """命中任何 enabled 的目录前缀策略即需加密（最长前缀优先）。"""
        path = norm_path(path)
        with self.meta.lock:
            for p in self._doc().get("policies", []):
                if not p.get("enabled"):
                    continue
                pp = p["path"]
                if path == pp or path.startswith(pp.rstrip("/") + "/"):
                    return True
        return False

    def matching_policy(self, path):
        path = norm_path(path)
        with self.meta.lock:
            best = None
            for p in self._doc().get("policies", []):
                if not p.get("enabled"):
                    continue
                pp = p["path"]
                if (path == pp or path.startswith(pp.rstrip("/") + "/")) and \
                        (best is None or len(pp) > len(best["path"])):
                    best = p
            return dict(best) if best else None

    # ---------------------------------------------------------------- 密钥
    def active_key_id(self):
        return self._keyring().get("active_id")

    def _get_record(self, key_id):
        rec = self._keyring().get("keys", {}).get(key_id)
        if not rec:
            raise EncryptionError(f"密钥不存在: {key_id}")
        return rec

    def get_dek(self, key_id):
        """按 key_id 取明文 DEK（先内存缓存，未命中则用 KEK 解包）。"""
        with self._cache_lock:
            cached = self._dek_cache.get(key_id)
        if cached is not None:
            return cached
        with self.meta.lock:
            rec = self._get_record(key_id)
            wrapped = rec["wrapped"]
        dek = unwrap_dek(self.master.kek, wrapped)
        if key_fingerprint(dek) != rec["fingerprint"]:
            raise EncryptionError("解包后密钥指纹不一致")
        with self._cache_lock:
            self._dek_cache[key_id] = dek
        return dek

    def active_dek(self):
        with self.meta.lock:
            key_id = self.active_key_id()
        if not key_id:
            raise EncryptionError("密钥环尚未初始化")
        return key_id, self.get_dek(key_id)

    def rotate_key(self, actor="admin", note=""):
        """
        轮换：生成新 DEK 置为 active；旧 active 标记 retired 但保留。
        - 旧块的块表记录旧 key_id，读取按 id 解旧 DEK → 历史文件持续可读；
        - 新写入一律取新 active；
        - 整个轮换是一次原子的元数据翻转，旧 DEK 不删除 ⇒ 无不可读窗口。
        返回 (new_rec, old_id)。
        """
        with self.meta.lock:
            kr = self._keyring()
            old_id = kr.get("active_id")
            if old_id:
                old = kr["keys"].get(old_id)
                if old and old.get("state") == "active":
                    old["state"] = "retired"
                    old["rotated_at"] = now()
            new_rec = self._build_key_record(
                generate_dek(), state="active", actor=actor,
                note=note or f"轮换自 {old_id or '-'}")
            kr["keys"][new_rec["id"]] = new_rec
            kr["active_id"] = new_rec["id"]
            self.meta.touch("encryption")
            # 预热缓存，保证轮换返回后新密钥立即可用
            self._dek_cache[new_rec["id"]] = unwrap_dek(
                self.master.kek, new_rec["wrapped"])
            return dict(new_rec), old_id

    def key_public_view(self, rec):
        """列表/摘要视图：绝不含 wrapped 或明文 DEK。"""
        return {
            "id": rec["id"],
            "alg": rec.get("alg"),
            "state": rec.get("state"),
            "version": rec.get("version"),
            "fingerprint": rec.get("fingerprint"),
            "brief": rec.get("brief"),
            "created_at": rec.get("created_at"),
            "rotated_at": rec.get("rotated_at"),
            "created_by": rec.get("created_by"),
            "note": rec.get("note", ""),
            "in_use_by_active": rec["id"] == self.active_key_id(),
        }

    def list_keys_view(self):
        with self.meta.lock:
            kr = self._keyring()
            recs = list(kr.get("keys", {}).values())
            active_id = kr.get("active_id")
        views = [self.key_public_view(r) for r in recs]
        views.sort(key=lambda v: v.get("created_at", 0), reverse=True)
        # 统计每个密钥保护的块数
        counts = self.block_key_counts()
        for v in views:
            v["protected_blocks"] = counts.get(v["id"], 0)
        return {"active_id": active_id, "keys": views,
                "kek_fingerprint": self.master.fingerprint()}

    def reveal_key(self, key_id):
        """
        完整明文 DEK —— 仅在路由层确认调用者为 admin（且二次校验口令）后调用。
        返回的字典只在单次 HTTP 响应中出现，调用方负责审计。
        """
        dek = self.get_dek(key_id)
        with self.meta.lock:
            rec = self._get_record(key_id)
            view = self.key_public_view(rec)
        view["material_b64"] = b64e(dek)
        view["material_hex"] = dek.hex()
        return view

    def block_key_counts(self):
        """统计块表中每个 key_id 的块数（页面展示密钥使用情况）。"""
        counts = {}
        with self.meta.lock:
            blocks = self.meta.get("blocks")
            for blk in blocks.get("blocks", {}).values():
                kid = (blk.get("enc") or {}).get("key_id")
                if kid:
                    counts[kid] = counts.get(kid, 0) + 1
        return counts

    # ---------------------------------------------------------------- 加解密
    def encrypt_chunks(self, chunks):
        """
        写路径：把 Chunk 列表原地加密为密文块。
        每块随机 nonce；加密后同明文不会去重（store 路径据此跳过 by_checksum）。
        返回 [(cipher, enc_meta)]，enc_meta = {alg,key_id,nonce_b64,
        plain_checksum, stored_checksum}，顺序与 chunks 对齐。
        """
        key_id, dek = self.active_dek()
        out = []
        for ch in chunks:
            plain = ch.data or b""
            nonce = new_nonce()
            cipher = aes_ctr_xor(dek, nonce, plain)
            out.append((cipher, {
                "alg": self.ALG,
                "key_id": key_id,
                "nonce": b64e(nonce),
                "plain_checksum": ch.checksum,         # 明文哈希：读路径验真
                "stored_checksum": sha256_bytes(cipher),  # 密文哈希：DN 对账
            }))
        return out

    def decrypt_block(self, cipher, enc_meta, offset=0):
        """
        读路径：按块记录的 key_id 找 DEK（可能是已退役旧密钥）解密。
        offset 为该段在整段密文中的字节偏移（Range 读透明 seek）。
        解密后由调用方用 plain_checksum 校验完整性。
        """
        if not enc_meta:
            return cipher
        key_id = enc_meta.get("key_id")
        nonce = b64d(enc_meta.get("nonce", ""))
        dek = self.get_dek(key_id)
        return aes_ctr_xor(dek, nonce, cipher, offset=offset)
