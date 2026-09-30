# -*- coding: utf-8 -*-
"""
keystore.py — 加密域（scope）与密钥版本链管理
================================================
数据模型（meta['crypto'] JSON 文档，仅存于 NameNode；
不加入 VERSION_VECTOR_SYNC_DOCS，DataNode 永远拿不到任何密钥材料）::

    {
      "scopes": {
        "/finance": {
          "path": "/finance",
          "enabled_at": 1234.0, "enabled_by": "admin",
          "current_kid": "kv_...",
          "keys": [
             {"kid": "kv_...", "version": 1,
              "key_b64": "<base64 32B>",      # 完整密钥，仅本进程可读
              "fingerprint": "<hex32>",
              "created_at": ..., "created_by": "admin",
              "rotated_from": null, "note": "初始密钥"}
          ]
        }
      },
      "revels": [ ...最近若干次明文查看审计摘要（不含密钥）... ]
    }

轮换语义（无停机窗口）：
  * rotate() 只做一件事——原子生成新密钥、追加进 keys、切换 current_kid；
    旧密钥一律保留，不删除、不覆盖；
  * 写入路径取 current_kid（新文件 = 新密钥）；
  * 读取路径按每个块容器头部记录的 kid 解析（旧文件 = 旧密钥）；
  * 因此轮换前后都不存在"读不出"的时刻，历史提交中的旧块同样永久可读。
"""

import base64
import threading

from . import crypto
from .util import gen_id, norm_path, now


class KeyStoreError(Exception):
    pass


class KeyStore:
    def __init__(self, nn):
        self.nn = nn
        self.meta = nn.meta
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ 基础
    def _doc(self):
        return self.meta.get("crypto")

    def ensure_seed(self):
        with self.meta.lock:
            doc = self._doc()
            doc.setdefault("scopes", {})
            doc.setdefault("revels", [])
            self.meta.touch("crypto")

    @staticmethod
    def _scope_key(path):
        return norm_path(path)

    def _get_scope(self, path):
        return self._doc().get("scopes", {}).get(self._scope_key(path))

    def _resolve_key(self, kid):
        """kid -> 密钥 bytes（遍历所有 scope 的密钥链）。"""
        for scope in self._doc().get("scopes", {}).values():
            for kv in scope.get("keys", []):
                if kv["kid"] == kid:
                    return base64.b64decode(kv["key_b64"])
        return None

    # ------------------------------------------------------------------ 域
    def enabled_paths(self):
        """当前已启用加密的目录列表（供前端目录树打标）。"""
        with self.meta.lock:
            return sorted(self._doc().get("scopes", {}).keys())

    def is_enabled(self, path):
        with self.meta.lock:
            return self._scope_key(path) in self._doc().get("scopes", {})

    def scope_of(self, path):
        """
        返回对 path 生效的加密域（最长前缀匹配）。
        无匹配返回 None（该路径落盘不加密）。
        """
        path = norm_path(path)
        with self.meta.lock:
            best = None
            for spath in self._doc().get("scopes", {}).keys():
                if path == spath or path.startswith(spath.rstrip("/") + "/"):
                    if best is None or len(spath) > len(best):
                        best = spath
            return best

    def enable_scope(self, path, actor="admin", note=""):
        """对目录启用落盘加密（幂等）。返回该 scope 的对外摘要。"""
        path = norm_path(path)
        with self.meta.lock:
            fs = self.meta.get("fs")
            inode = None
            from .filesystem import FsError
            try:
                inode = self.nn.fs.resolve(path)
            except FsError:
                pass
            if inode is not None and inode.get("type") != "dir":
                raise KeyStoreError(f"只能对目录启用加密: {path}")
            scopes = self._doc().setdefault("scopes", {})
            if path in scopes:
                return self.scope_view(path)
            kid = gen_id("kv")
            key = crypto.generate_key()
            entry = {
                "path": path,
                "enabled_at": now(), "enabled_by": actor,
                "current_kid": kid,
                "note": note or "",
                "keys": [{
                    "kid": kid, "version": 1,
                    "key_b64": base64.b64encode(key).decode("ascii"),
                    "fingerprint": crypto.key_fingerprint(key),
                    "alg": "HMAC-SHA256-CTR",
                    "created_at": now(), "created_by": actor,
                    "rotated_from": None,
                    "note": "初始密钥",
                }],
            }
            scopes[path] = entry
            self.meta.touch("crypto")
            self.nn.log_event("WARN", "crypto", "enable_scope", path, actor,
                             f"目录启用落盘加密，初始密钥 {kid}")
            return self.scope_view(path)

    # ------------------------------------------------------------------ 轮换
    def rotate(self, path, actor="admin", note=""):
        """
        轮换：生成新版本密钥并切换 current_kid；旧版本永久保留。
        """
        path = norm_path(path)
        with self.meta.lock:
            scope = self._get_scope(path)
            if not scope:
                raise KeyStoreError(f"目录未启用加密: {path}")
            old_kid = scope["current_kid"]
            old_version = len(scope["keys"])
            kid = gen_id("kv")
            key = crypto.generate_key()
            version = old_version + 1
            scope["keys"].append({
                "kid": kid, "version": version,
                "key_b64": base64.b64encode(key).decode("ascii"),
                "fingerprint": crypto.key_fingerprint(key),
                "alg": "HMAC-SHA256-CTR",
                "created_at": now(), "created_by": actor,
                "rotated_from": old_kid,
                "note": note or f"第 {version} 次轮换",
            })
            scope["current_kid"] = kid
            self.meta.touch("crypto")
            self.nn.log_event("WARN", "crypto", "key_rotate", path, actor,
                             f"密钥轮换 v{old_version}->{version}；"
                             f"旧密钥保留，历史块仍可读")
            return self.scope_view(path)

    def current_key(self, path):
        """取某加密域当前密钥（写路径）。返回 (kid, key_bytes)。"""
        with self.meta.lock:
            scope = self._get_scope(path)
            if not scope:
                raise KeyStoreError(f"目录未启用加密: {path}")
            kid = scope["current_kid"]
            return kid, self._resolve_key(kid)

    # ------------------------------------------------------------------ 摘要
    @staticmethod
    def _key_brief(kv):
        return {
            "kid": kv["kid"], "version": kv["version"],
            "fingerprint": kv["fingerprint"],
            "fingerprint_short": kv["fingerprint"][:12],
            "alg": kv.get("alg", "HMAC-SHA256-CTR"),
            "created_at": kv.get("created_at"),
            "created_by": kv.get("created_by"),
            "note": kv.get("note", ""),
            "is_current": False,       # 由调用方按 scope 标记
        }

    def scope_view(self, path):
        """单个加密域的对外摘要（不含任何密钥材料）。"""
        with self.meta.lock:
            scope = self._get_scope(path)
            if not scope:
                raise KeyStoreError(f"目录未启用加密: {path}")
            keys = [self._key_brief(kv) for kv in scope["keys"]]
            for k in keys:
                k["is_current"] = k["kid"] == scope["current_kid"]
            return {
                "path": scope["path"],
                "enabled_at": scope.get("enabled_at"),
                "enabled_by": scope.get("enabled_by"),
                "current_kid": scope["current_kid"],
                "current_version": next(
                    (k["version"] for k in keys if k["is_current"]), 1),
                "versions": len(keys),
                "keys": keys,
                "note": scope.get("note", ""),
            }

    def list_scopes(self):
        with self.meta.lock:
            return [self.scope_view(p)
                    for p in sorted(self._doc().get("scopes", {}).keys())]

    def encryption_overview(self):
        """
        加密总览：域列表 + 每个密钥版本下的块数/明文字节统计。
        统计来自 NN 块表（块记录了 enc_kid 与 plain_size）。
        """
        with self.meta.lock:
            scopes = self.list_scopes()
            blocks = self.meta.get("blocks")["blocks"]
            per_kid = {}
            for blk in blocks.values():
                kid = blk.get("enc_kid")
                if not kid:
                    continue
                st = per_kid.setdefault(kid, {"blocks": 0, "plain_bytes": 0,
                                              "cipher_bytes": 0})
                st["blocks"] += 1
                st["plain_bytes"] += blk.get("plain_size", blk.get("size", 0))
                st["cipher_bytes"] += blk.get("size", 0)
            for scope in scopes:
                for k in scope["keys"]:
                    k["usage"] = per_kid.get(k["kid"],
                                             {"blocks": 0, "plain_bytes": 0,
                                              "cipher_bytes": 0})
            return {
                "scopes": scopes,
                "enabled_paths": [s["path"] for s in scopes],
                "alg": "HMAC-SHA256-CTR（每块随机 nonce + HMAC 认证标签）",
                "cipher_on_datanode": True,
            }

    # ------------------------------------------------------------------ 加解密
    def seal_for_path(self, path, plaintext):
        """写路径：若 path 命中加密域则封包；否则原样返回（明文块）。"""
        scope_path = self.scope_of(path)
        if not scope_path:
            return plaintext, None
        kid, key = self.current_key(scope_path)
        return crypto.seal_block(plaintext, key, kid), kid

    def open_blob(self, blob):
        """读路径：密文容器则透明解密；裸明文块原样返回。"""
        if not crypto.is_encrypted_blob(blob):
            return blob, {"encrypted": False}
        plaintext, info = crypto.open_block(blob, self._resolve_key)
        info["encrypted"] = True
        return plaintext, info

    def key_of_kid(self, kid):
        """供内部按 kid 取密钥（需要时）。"""
        with self.meta.lock:
            return self._resolve_key(kid)

    # ------------------------------------------------------------------ 查看明文密钥
    def reveal_key(self, scope_path, kid, user, reason=""):
        """
        管理员显式查看完整密钥（明文）。
        调用方必须先完成管理员口令再确认（HTTP 层做）；这里只做最后审计。
        返回 {"key_b64", "key_hex", ...}。
        """
        scope_path = norm_path(scope_path)
        with self.meta.lock:
            scope = self._get_scope(scope_path)
            if not scope:
                raise KeyStoreError(f"目录未启用加密: {scope_path}")
            kv = next((k for k in scope["keys"] if k["kid"] == kid), None)
            if not kv:
                raise KeyStoreError(f"{scope_path} 下不存在密钥版本 {kid}")
            key = base64.b64decode(kv["key_b64"])
            revels = self._doc().setdefault("revels", [])
            revels.append({"ts": now(), "user": user, "scope": scope_path,
                           "kid": kid, "version": kv["version"],
                           "reason": (reason or "")[:200]})
            self._doc()["revels"] = revels[-100:]
            self.meta.touch("crypto")
            self.nn.log_event("WARN", "crypto", "key_reveal", scope_path,
                             user,
                             f"查看密钥明文 v{kv['version']} {kid}，"
                             f"原因：{reason or '（未填写）'}")
            return {
                "scope": scope_path, "kid": kid, "version": kv["version"],
                "key_b64": kv["key_b64"],
                "key_hex": key.hex(),
                "fingerprint": kv["fingerprint"],
                "alg": kv.get("alg", "HMAC-SHA256-CTR"),
            }

    def recent_revels(self, limit=20):
        with self.meta.lock:
            return list(reversed(self._doc().get("revels", [])[-limit:]))
