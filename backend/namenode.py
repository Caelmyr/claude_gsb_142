# -*- coding: utf-8 -*-
"""
namenode.py — NameNode：元数据与集群协调核心
================================================
职责（对应五大难点）：
  * 块表管理：block -> {size, checksum, genstamp, desired, replicas:{node:{...}}}
    副本状态机 ok / corrupt / stale，genstamp 单调递增防止旧副本复活；
  * 副本放置策略：跨机架优先 + 剩余空间优先 + 负载扰动（难点一）；
  * 写路径：分块（chunking）-> 按校验和去重 -> 流水线复制
    （PUT dn1 -> dn1 转发 dn2 -> ... 每跳校验 sha256）；
  * 读路径：副本轮询 + 校验失败自动故障转移（难点一/二）；
  * 心跳管理：注册节点、判活（HEARTBEAT_TIMEOUT）、处理事件
    （replicate_done / corrupt / deleted / doc_synced ...）、下发命令；
  * 块汇报对账：全量比对 DN 库存与块表，未知/过期/损坏块下发删除，
    缺失副本进入恢复队列（难点二：故障检测与自动恢复）；
  * 恢复调度：under-replicated 队列 -> 选择存活源副本 -> 通过心跳命令
    让目标节点 HTTP 拉取复制；
  * 分块上传会话（断点续传）与 Range 下载；
  * GC：引用集 = 活动 inode ∪ 全部提交快照 ∪ 进行中会话，
    未引用块过宽限期后下发删除（难点三配套）；
  * 热度/容量统计（存储统计页数据源）；
  * 元数据文档：MetadataStore（原子写 + 版本向量），cluster 文档
    向 DataNode 同步（难点五）；
  * 审计日志：内存 ring + logs 文档延迟刷盘。
"""

import json
import os
import random
import threading

from . import chunking, config
from .auth import AuthManager, PermissionManager
from .filesystem import FsError, VirtualFS
from .keystore import KeyStore, KeyStoreError
from .metadata import MetadataStore
from .util import (HttpError, LRU, RateCounter, RingBuffer, b64e, gen_id,
                   guess_mime, hour_key, http_json, http_request,
                   is_text_mime, needs_recovery, canonical_access_op,
                   now, parse_range, sha256_bytes, short_hash, split_multi,
                   vv_compare, vv_merge)
from .versioning import VersionStore


class NNError(Exception):
    pass


class MissingBlockError(NNError):
    pass


class NameNode:
    def __init__(self, host=None, port=None, data_dir=None, meta_dir=None,
                 cluster_key=None):
        self.host = host or config.HOST
        self.port = port or config.NAMENODE_PORT
        self.data_dir = data_dir or config.DATA_DIR
        self.meta_dir = meta_dir or config.META_DIR
        self.cluster_key = cluster_key or config.CLUSTER_KEY
        self.node_id = "namenode"
        self.started_at = now()

        os.makedirs(self.meta_dir, exist_ok=True)
        os.makedirs(config.SESSION_DIR, exist_ok=True)

        # ---- 元数据 ----
        self.meta = MetadataStore(self.meta_dir, node_id=self.node_id)
        self.fs = VirtualFS(self.meta)
        self.auth = AuthManager(self.meta)
        self.perms = PermissionManager(self.meta, self.auth)
        self.keys = KeyStore(self)
        self.versions = VersionStore(self)

        # ---- 节点注册表（内存态；摘要持久化到 cluster 文档） ----
        self.nodes = {}                  # node_id -> NodeInfo dict
        self.node_lock = threading.RLock()

        # ---- 命令队列：随下次心跳下发 ----
        self.pending_commands = {}       # node_id -> [cmd]
        self.cmd_lock = threading.Lock()

        # ---- 健康状态 ----
        self.under_replicated = {}       # bid -> {"since": ts, "attempts": n}
        self.corrupt_replicas = {}       # (bid, node) -> info
        self.missing_blocks = set()      # 无任何存活好副本
        self.scheduled = {}              # bid -> {"src","dst","at"}
        self.health_lock = threading.RLock()

        # ---- 运行态 ----
        self.events = RingBuffer(config.EVENT_RING_SIZE)
        self.block_cache = LRU(maxsize=512, max_bytes=96 * 1024 * 1024)
        self.sessions = {}               # 上传会话
        self.session_lock = threading.RLock()
        self._rr_counter = 0
        self.api_rate = RateCounter(window=10)
        self.local_datanodes = {}        # 同进程 DN 实例（演练用）
        self.httpd = None
        self._threads = []
        self._stop = threading.Event()
        self.sim_chaos = False           # 前端"混沌模式"：上传随机失败

    # ==================================================================
    # 启动 / 停止
    # ==================================================================
    def start(self, with_http=True):
        self.fs.init_root()
        self.auth.ensure_seed()
        self.perms.ensure_seed()
        self.keys.ensure_seed()
        self.versions.ensure_head()
        self._init_blocks_doc()
        self._init_stats_doc()
        self.meta.start_flusher()

        for target, name in (
                (self._liveness_loop, "nn-liveness"),
                (self._recovery_loop, "nn-recovery"),
                (self._gc_loop, "nn-gc"),
                (self._stats_loop, "nn-stats"),
                (self._trash_loop, "nn-trash"),
                (self._session_gc_loop, "nn-session-gc")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

        if with_http:
            from .http_server import start_namenode_server
            self.httpd = start_namenode_server(self)
        self.log_event("INFO", "namenode", "start", self.node_id, "system",
                       f"NameNode 启动 @ {self.host}:{self.port}")
        self.emit("namenode_start", f"NameNode 启动 @ {self.host}:{self.port}")

    def stop(self):
        self._stop.set()
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
        self.meta.stop()
        self.log_event("INFO", "namenode", "stop", self.node_id, "system",
                       "NameNode 停止")

    def _init_blocks_doc(self):
        with self.meta.lock:
            blocks = self.meta.get("blocks")
            blocks.setdefault("blocks", {})
            blocks.setdefault("by_checksum", {})     # 明文块内容去重索引
            blocks.setdefault("by_plain_kid", {})    # 加密块按 (kid,明文校验和) 去重
            blocks.setdefault("next_genstamp", 1000)
            self.meta.touch("blocks", flush=False)

    def _init_stats_doc(self):
        with self.meta.lock:
            stats = self.meta.get("stats")
            stats.setdefault("access", [])
            stats.setdefault("hourly", {})
            stats.setdefault("capacity_history", [])
            self.meta.touch("stats", flush=False)

    # ==================================================================
    # 日志 / 事件
    # ==================================================================
    def log_event(self, level, source, action, target, user, detail=""):
        entry = {
            "ts": now(), "level": level, "source": source, "action": action,
            "target": target or "", "user": user or "system",
            "detail": (detail or "")[:2000],
        }
        with self.meta.lock:
            logs = self.meta.get("logs")
            items = logs.setdefault("items", [])
            items.append(entry)
            if len(items) > config.LOG_MAX_ENTRIES:
                logs["items"] = items[-config.LOG_MAX_ENTRIES:]
            self.meta.touch("logs", flush=False)
        return entry

    def emit(self, kind, message, **data):
        """集群事件流（节点页实时展示）。"""
        self.events.append({"ts": now(), "kind": kind, "message": message,
                            **data})

    def query_logs(self, level=None, source=None, user=None, q=None,
                   limit=100, offset=0):
        if isinstance(level, str):
            level = split_multi(level, config.LOG_LEVEL_SEP) or None
        with self.meta.lock:
            items = list(self.meta.get("logs").get("items", []))
        items.reverse()
        if level:
            items = [i for i in items if i["level"] in level]
        if source:
            items = [i for i in items if i["source"] == source]
        if user:
            items = [i for i in items if i.get("user") == user]
        if q:
            ql = q.lower()
            items = [i for i in items
                     if ql in json.dumps(i, ensure_ascii=False).lower()]
        total = len(items)
        return {"total": total, "items": items[offset:offset + limit]}

    def clear_logs(self):
        with self.meta.lock:
            self.meta.get("logs")["items"] = []
            self.meta.touch("logs")

    # ==================================================================
    # 节点注册表 / 心跳（难点二：故障检测）
    # ==================================================================
    def handle_heartbeat(self, payload):
        node_id = payload.get("node_id")
        if not node_id:
            raise NNError("缺少 node_id")
        just_registered = False
        just_revived = None
        with self.node_lock:
            node = self.nodes.get(node_id)
            was_state = node["state"] if node else None
            if node is None:
                node = self._register_node(payload)
                just_registered = True
            node.update({
                "rack": payload.get("rack", node.get("rack", "rack-?")),
                "url": payload.get("url", node["url"]),
                "port": payload.get("port", node.get("port")),
                "storage": payload.get("storage", {}),
                "block_count": payload.get("block_count", 0),
                "io": payload.get("io", {}),
                "rates": payload.get("rates", {}),
                "uptime": payload.get("uptime", 0),
                "vv": vv_merge(node.get("vv", {}), payload.get("vv", {})),
                "doc_vv": payload.get("doc_vv", {}),
                "last_seen": now(),
                "hb_count": node.get("hb_count", 0) + 1,
            })
            hb_count = node["hb_count"]
            if node["state"] != "LIVE":
                node["state"] = "LIVE"
                if was_state in ("DEAD", "SUSPECT"):
                    just_revived = dict(node)
            if node.get("killed_flag"):
                node["killed_flag"] = False

        # 锁外执行（保持全局锁序 meta > node > health > cmd，避免 ABBA 死锁）
        if just_registered:
            self._update_cluster_doc()
        if just_revived is not None:
            self._on_node_revived(just_revived)
        if hb_count % 4 == 0:
            self.emit("hb", f"节点 {node_id} 心跳正常 #{hb_count}",
                      node=node_id)

        # 处理捎带事件
        for event in payload.get("events", []):
            self._handle_node_event(node_id, event)

        # 组装应答：命令 + 需要拉取的同步文档
        commands = self._drain_commands(node_id)
        pull_docs = self._docs_to_sync(payload.get("doc_vv", {}))
        return {"ok": True, "nn_time": now(), "commands": commands,
                "pull_docs": pull_docs}

    def _register_node(self, payload):
        node_id = payload["node_id"]
        node = {
            "node_id": node_id,
            "rack": payload.get("rack", "rack-?"),
            "url": payload.get("url", ""),
            "port": payload.get("port"),
            "state": "LIVE",
            "registered_at": now(),
            "last_seen": now(),
            "hb_count": 0,
            "storage": payload.get("storage", {}),
            "block_count": 0,
            "io": {}, "rates": {}, "uptime": 0,
            "vv": payload.get("vv", {}),
            "doc_vv": {},
            "deaths": 0,
            "killed_flag": False,
        }
        self.nodes[node_id] = node
        # 注意：不在 node_lock 内调用 _update_cluster_doc（锁序 meta > node），
        # 由 handle_heartbeat 在释放 node_lock 后统一更新。
        self.log_event("INFO", "namenode", "node_register", node_id, "system",
                       f"DataNode {node_id} 注册 rack={node['rack']}")
        self.emit("node_register", f"节点 {node_id} 注册加入集群",
                  node=node_id)
        return node

    def _on_node_revived(self, node):
        node_id = node["node_id"]
        self.log_event("INFO", "recovery", "node_revived", node_id, "system",
                       f"节点 {node_id} 恢复心跳，重新标记 LIVE，要求全量块汇报")
        self.emit("node_revived", f"节点 {node_id} 复活", node=node_id)
        self._enqueue_command(node_id, {"type": "report"})
        # 该节点上的副本重新纳入健康评估（不持锁调用，check_block_health 自会加锁）
        self._rescan_all_blocks()

    def mark_node_dead(self, node_id):
        with self.node_lock:
            node = self.nodes.get(node_id)
            if not node or node["state"] == "DEAD":
                return
            node["state"] = "DEAD"
            node["deaths"] = node.get("deaths", 0) + 1
            node["dead_at"] = now()
        self._update_cluster_doc()
        self.log_event("ERROR", "recovery", "node_dead", node_id, "system",
                       f"心跳超时（>{config.HEARTBEAT_TIMEOUT}s），判定 DEAD；"
                       f"启动副本恢复")
        self.emit("node_dead", f"节点 {node_id} 心跳超时被判定 DEAD",
                  node=node_id)
        self._handle_node_failure(node_id)

    def _handle_node_failure(self, dead_node):
        """节点故障：其上的副本全部失效，低于期望副本数的块进入恢复队列。"""
        affected = 0
        with self.meta.lock:
            blocks = self.meta.get("blocks")["blocks"]
            for bid, blk in blocks.items():
                reps = blk.get("replicas", {})
                if dead_node in reps:
                    affected += 1
                    self.check_block_health(bid)
        self.emit("recovery_start",
                  f"节点 {dead_node} 故障波及 {affected} 个块，开始再复制",
                  node=dead_node, affected=affected)
        self.log_event("WARN", "recovery", "failure_scan", dead_node, "system",
                       f"故障扫描：{affected} 个块受影响")

    def _liveness_loop(self):
        while not self._stop.is_set():
            self._stop.wait(1.0)
            t = now()
            with self.node_lock:
                for node_id, node in self.nodes.items():
                    if node["state"] == "DEAD":
                        continue
                    silence = t - node.get("last_seen", 0)
                    if silence > config.HEARTBEAT_TIMEOUT:
                        self.mark_node_dead(node_id)
                    elif silence > config.HEARTBEAT_TIMEOUT * 0.6 \
                            and node["state"] == "LIVE":
                        node["state"] = "SUSPECT"

    def _handle_node_event(self, node_id, event):
        etype = event.get("type")
        if etype == "replicate_done":
            bid = event.get("block_id")
            with self.meta.lock:
                blk = self.meta.get("blocks")["blocks"].get(bid)
                if blk:
                    self._record_replica(bid, blk, node_id,
                                         event.get("genstamp", blk["genstamp"]),
                                         event.get("checksum", blk["checksum"]),
                                         event.get("size", blk["size"]), "ok")
                    self.meta.touch("blocks", flush=False)
            self.check_block_health(bid)
            self.scheduled.pop(bid, None)
            self.emit("replicate_done",
                      f"块 {short_hash(bid, 12)} 成功复制到 {node_id}",
                      node=node_id, block=bid)
        elif etype == "replicate_failed":
            bid = event.get("block_id")
            self.scheduled.pop(bid, None)
            self.check_block_health(bid)
            self.log_event("WARN", "recovery", "replicate_failed",
                           bid or "", "system",
                           f"{node_id}: {event.get('reason', '')}")
        elif etype == "corrupt":
            bid = event.get("block_id")
            with self.meta.lock:
                blk = self.meta.get("blocks")["blocks"].get(bid)
                if blk and node_id in blk.get("replicas", {}):
                    blk["replicas"][node_id]["state"] = "corrupt"
                    blk["replicas"][node_id]["updated_at"] = now()
                    self.meta.touch("blocks", flush=False)
            with self.health_lock:
                self.corrupt_replicas[(bid, node_id)] = {
                    "reason": event.get("reason", ""), "ts": now()}
            self.check_block_health(bid)
            self.log_event("ERROR", "block", "corrupt", f"{bid}@{node_id}",
                           "system", event.get("reason", ""))
            self.emit("corrupt", f"节点 {node_id} 发现块 {short_hash(bid, 12)} 损坏",
                      node=node_id, block=bid)
        elif etype == "deleted":
            bid = event.get("block_id")
            with self.meta.lock:
                blk = self.meta.get("blocks")["blocks"].get(bid)
                if blk and node_id in blk.get("replicas", {}):
                    del blk["replicas"][node_id]
                    self.meta.touch("blocks", flush=False)
            self.check_block_health(bid)
        elif etype == "doc_synced":
            self.log_event("DEBUG", "sync", "doc_synced",
                           event.get("doc", ""), "system",
                           f"{node_id}: relation={event.get('relation')} "
                           f"vv={event.get('vv')}")
        elif etype == "hb_failed":
            pass    # DN 侧连不上 NN 的记录（NN 收到时已恢复，忽略）
        elif etype == "revived":
            self.emit("node_revived", f"节点 {node_id} 重启完成", node=node_id)

    # ==================================================================
    # 块汇报对账（难点一/二：副本一致性）
    # ==================================================================
    def handle_block_report(self, payload):
        node_id = payload.get("node_id")
        if not node_id:
            raise NNError("缺少 node_id")
        commands = []
        reported = set()
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            blocks = blocks_doc["blocks"]
            touched = False
            for rep in payload.get("blocks", []):
                bid = rep["id"]
                reported.add(bid)
                blk = blocks.get(bid)
                if not blk:
                    commands.append({"type": "delete", "block_id": bid,
                                     "reason": "namenode 块表中不存在"})
                    continue
                if rep.get("genstamp", 0) < blk.get("genstamp", 0):
                    commands.append({"type": "delete", "block_id": bid,
                                     "reason": "genstamp 过期（stale replica）"})
                    continue
                old = blk.get("replicas", {}).get(node_id)
                state = rep.get("state", "ok")
                if rep.get("checksum") != blk.get("checksum"):
                    state = "corrupt"
                if (not old or old.get("checksum") != rep.get("checksum")
                        or old.get("state") != state):
                    touched = True
                self._record_replica(bid, blk, node_id, rep.get("genstamp"),
                                     rep.get("checksum"), rep.get("size"),
                                     state)
                if state == "corrupt":
                    commands.append({"type": "delete", "block_id": bid,
                                     "reason": "校验和不匹配（损坏副本清除）"})
            # 块表认为该节点应有、但汇报中缺失的副本 => 从副本表移除
            for bid, blk in blocks.items():
                if bid in reported:
                    continue
                if node_id in blk.get("replicas", {}):
                    del blk["replicas"][node_id]
                    touched = True
            # 孤儿块（磁盘有、索引外）
            for bid in payload.get("orphans", []):
                commands.append({"type": "delete", "block_id": bid,
                                 "reason": "孤儿块"})
            if touched:
                self.meta.touch("blocks", flush=False)
        with self.node_lock:
            node = self.nodes.get(node_id)
            if node:
                node["last_report_at"] = now()
                node["block_count"] = len(payload.get("blocks", []))
        # 汇报后重估相关块健康度
        for bid in reported:
            self.check_block_health(bid)
        return {"ok": True, "commands": commands,
                "accepted": len(reported),
                "delete_commands": len(commands)}

    def _record_replica(self, bid, blk, node_id, genstamp, checksum, size,
                        state):
        """写入/更新副本记录（调用方持 meta.lock）。"""
        reps = blk.setdefault("replicas", {})
        reps[node_id] = {
            "genstamp": int(genstamp or blk.get("genstamp", 1)),
            "checksum": checksum or blk.get("checksum"),
            "size": size if size is not None else blk.get("size", 0),
            "state": state,
            "updated_at": now(),
        }

    # ==================================================================
    # 健康度 / 恢复调度（难点二）
    # ==================================================================
    def live_nodes(self):
        with self.node_lock:
            return [n for n in self.nodes.values() if n["state"] == "LIVE"]

    def live_good_replicas(self, blk):
        """存活且状态 ok、genstamp 匹配的副本节点列表。"""
        good = []
        live_ids = {n["node_id"] for n in self.live_nodes()}
        for nid, rep in list((blk.get("replicas") or {}).items()):
            if nid not in live_ids:
                continue
            if rep.get("state") != "ok":
                continue
            if rep.get("genstamp", 0) != blk.get("genstamp", 0):
                continue
            good.append(nid)
        return good

    def check_block_health(self, bid):
        """评估单块健康度，维护 under_replicated / missing 集合。"""
        with self.meta.lock:
            blk = self.meta.get("blocks")["blocks"].get(bid)
        if not blk:
            with self.health_lock:
                self.under_replicated.pop(bid, None)
                self.missing_blocks.discard(bid)
            return None
        good = self.live_good_replicas(blk)
        desired = blk.get("desired", config.DEFAULT_REPLICATION)
        state = "healthy"
        with self.health_lock:
            if not good:
                self.missing_blocks.add(bid)
                self.under_replicated[bid] = self.under_replicated.get(
                    bid, {"since": now(), "attempts": 0})
                state = "missing"
            else:
                self.missing_blocks.discard(bid)
                if needs_recovery(len(good), desired, config.MIN_REPLICATION,
                                  config.RECOVERY_TRIGGER):
                    if bid not in self.under_replicated:
                        self.under_replicated[bid] = {"since": now(),
                                                      "attempts": 0}
                    state = ("critical" if len(good) < config.MIN_REPLICATION
                             else "under")
                else:
                    self.under_replicated.pop(bid, None)
                    self.scheduled.pop(bid, None)
                    # 块已恢复满副本：清理其历史损坏记录
                    for key in [k for k in self.corrupt_replicas
                                if k[0] == bid]:
                        del self.corrupt_replicas[key]
        return {"block": bid, "state": state, "live": len(good),
                "desired": desired}

    def _rescan_all_blocks(self):
        with self.meta.lock:
            bids = list(self.meta.get("blocks")["blocks"].keys())
        for bid in bids:
            self.check_block_health(bid)

    def _recovery_loop(self):
        """周期扫描恢复队列：为缺副本的块安排 源->目标 复制命令。"""
        while not self._stop.is_set():
            self._stop.wait(config.RECOVERY_SCAN_INTERVAL)
            try:
                self._schedule_recovery_once()
            except Exception as e:  # noqa: BLE001
                self.log_event("ERROR", "recovery", "loop_error", "", "system",
                               str(e))

    def _schedule_recovery_once(self):
        with self.health_lock:
            queue = list(self.under_replicated.items())
        if not queue:
            return
        live = self.live_nodes()
        if not live:
            return
        live_ids = {n["node_id"] for n in live}
        scheduled_now = 0
        for bid, info in queue:
            if scheduled_now >= 64:      # 单轮限流，防止心跳应答过大
                break
            with self.meta.lock:
                blk = self.meta.get("blocks")["blocks"].get(bid)
            if not blk:
                with self.health_lock:
                    self.under_replicated.pop(bid, None)
                continue
            good = self.live_good_replicas(blk)
            desired = blk.get("desired", config.DEFAULT_REPLICATION)
            if len(good) >= desired:
                with self.health_lock:
                    self.under_replicated.pop(bid, None)
                    self.scheduled.pop(bid, None)
                continue
            # 超时重排
            sched = self.scheduled.get(bid)
            if sched and now() - sched["at"] < config.REPLICATION_TIMEOUT:
                continue
            # 第一步：清理存活节点上的坏副本（corrupt / genstamp 过期），
            # 先下发删除命令并摘除副本记录，使这些节点重新成为复制候选。
            good_set = set(good)
            with self.meta.lock:
                blk2 = self.meta.get("blocks")["blocks"].get(bid)
                if blk2:
                    reps = blk2.get("replicas") or {}
                    for nid in list(reps.keys()):
                        if nid in good_set or nid not in live_ids:
                            continue
                        self._enqueue_command(nid, {
                            "type": "delete", "block_id": bid,
                            "reason": "坏副本（corrupt/stale），删除后重建"})
                        del reps[nid]
                    self.meta.touch("blocks", flush=False)
            have = good_set
            candidates = [n for n in live
                          if n["node_id"] not in have
                          and n.get("storage", {}).get("free", 0)
                          > blk.get("size", 0)]
            if not candidates or not good:
                continue
            need = desired - len(good)
            src = random.choice(good)
            targets = self._rank_targets(candidates, blk.get("size", 0),
                                         count=need)
            src_url = self._node_url(src)
            for tnode in targets:
                cmd = {"type": "replicate", "block_id": bid, "src": src_url,
                       "genstamp": blk.get("genstamp", 1),
                       "checksum": blk.get("checksum"),
                       "size": blk.get("size")}
                self._enqueue_command(tnode["node_id"], cmd)
                scheduled_now += 1
            with self.health_lock:
                self.scheduled[bid] = {"src": src,
                                       "dst": [t["node_id"] for t in targets],
                                       "at": now()}
                info["attempts"] = info.get("attempts", 0) + 1
            self.emit("recovery_scheduled",
                      f"块 {short_hash(bid, 12)} 恢复调度: {src} -> "
                      f"{','.join(t['node_id'] for t in targets)}",
                      block=bid, src=src)

    def _enqueue_command(self, node_id, cmd):
        with self.cmd_lock:
            q = self.pending_commands.setdefault(node_id, [])
            q.append(cmd)
            if len(q) > 500:
                del q[:len(q) - 500]

    def _drain_commands(self, node_id):
        with self.cmd_lock:
            cmds = self.pending_commands.pop(node_id, [])
        return cmds

    # ==================================================================
    # 文档同步（版本向量，难点五）
    # ==================================================================
    def _update_cluster_doc(self):
        """把节点注册表摘要写入 cluster 文档（DataNode 会按 vv 拉取）。"""
        with self.meta.lock:
            cluster = self.meta.get("cluster")
            with self.node_lock:
                cluster["nodes"] = {
                    nid: {"rack": n["rack"], "state": n["state"],
                          "url": n["url"], "registered_at": n["registered_at"]}
                    for nid, n in self.nodes.items()}
            cluster["updated_by"] = self.node_id
            cluster["nn_started_at"] = self.started_at
            cluster["settings"] = {
                "block_size": config.BLOCK_SIZE,
                "replication": config.DEFAULT_REPLICATION,
                "heartbeat_timeout": config.HEARTBEAT_TIMEOUT,
            }
            self.meta.touch("cluster")

    def _docs_to_sync(self, dn_doc_vv):
        """比较版本向量，返回 DN 需要拉取的文档名列表。"""
        pull = []
        with self.meta.lock:
            for doc in config.VERSION_VECTOR_SYNC_DOCS:
                local = self.meta.doc(doc).vv
                remote = (dn_doc_vv or {}).get(doc, {})
                rel = vv_compare(local, remote)
                if rel in ("after", "concurrent"):
                    pull.append(doc)
        return pull

    def get_meta_doc(self, doc):
        # 仅允许向 DataNode 同步白名单内的文档；crypto 文档含数据密钥，
        # 即使持有集群密钥也绝不能经内部接口导出。
        if doc not in config.VERSION_VECTOR_SYNC_DOCS:
            raise NNError(f"文档不允许同步到 DataNode: {doc}")
        return self.meta.export_doc(doc)

    # ==================================================================
    # 副本放置 / 块分配（难点一）
    # ==================================================================
    def _node_url(self, node_id):
        with self.node_lock:
            n = self.nodes.get(node_id)
        return (n or {}).get("url", "")

    def _rank_targets(self, candidates, size, count):
        """跨机架优先 + 剩余空间优先 + 少量随机扰动。"""
        def score(n):
            free = n.get("storage", {}).get("free", 0)
            cap = n.get("storage", {}).get("capacity", 1) or 1
            usage = 1 - (free / cap)
            return (usage + random.random() * 0.05, n.get("rack"))
        ranked = sorted(candidates, key=score)
        chosen, racks = [], set()
        for n in ranked:                       # 第一轮：机架去重
            if len(chosen) >= count:
                break
            if n.get("rack") not in racks:
                chosen.append(n)
                racks.add(n.get("rack"))
        for n in ranked:                       # 第二轮：机架不够再补
            if len(chosen) >= count:
                break
            if n not in chosen:
                chosen.append(n)
        return chosen

    def choose_targets(self, size, count=None, exclude=()):
        count = count or config.DEFAULT_REPLICATION
        live = [n for n in self.live_nodes() if n["node_id"] not in exclude
                and n.get("storage", {}).get("free", 0) > size]
        if not live:
            raise NNError("没有满足空间要求的存活节点，无法放置副本")
        return self._rank_targets(live, size, min(count, len(live)))

    def allocate_block(self, size, checksum, desired=None, genstamp=None,
                       plain_checksum=None, plain_size=None, enc_kid=None):
        """
        在块表登记新块（副本随后通过流水线复制填充）。
        size/checksum 指**落盘字节**（加密块即密文容器），供 DataNode 对账；
        加密块额外记录 plain_checksum / plain_size / enc_kid。
        """
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            blocks = blocks_doc["blocks"]
            bid = gen_id("blk")
            while bid in blocks:
                bid = gen_id("blk")
            gs = genstamp or blocks_doc.get("next_genstamp", 1000)
            blocks_doc["next_genstamp"] = gs + 1
            entry = {
                "id": bid, "size": size, "checksum": checksum,
                "genstamp": gs,
                "desired": desired or config.DEFAULT_REPLICATION,
                "created_at": now(),
                "replicas": {},
            }
            if enc_kid:
                entry["encrypted"] = True
                entry["enc_kid"] = enc_kid
                entry["plain_checksum"] = plain_checksum
                entry["plain_size"] = plain_size if plain_size is not None \
                    else size
            blocks[bid] = entry
            self.meta.touch("blocks")
            return bid, gs

    def register_existing_checksum(self, checksum):
        """明文内容去重：同校验和的明文块已存在则直接复用。"""
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            bid = blocks_doc.get("by_checksum", {}).get(checksum)
            if bid and bid in blocks_doc["blocks"]:
                blk = blocks_doc["blocks"][bid]
                if not blk.get("encrypted") and self.live_good_replicas(blk):
                    return bid
            return None

    def register_existing_encrypted(self, kid, plain_checksum):
        """
        加密块去重：仅在「同一密钥版本 + 同一明文内容」时复用。
        不同 kid（轮换后）不复用——新写入必须使用新当前密钥。
        """
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            index = blocks_doc.get("by_plain_kid", {})
            bid = index.get(f"{kid}|{plain_checksum}")
            if bid and bid in blocks_doc["blocks"]:
                blk = blocks_doc["blocks"][bid]
                if blk.get("enc_kid") == kid and self.live_good_replicas(blk):
                    return bid
            return None

    # ==================================================================
    # 写路径：流水线复制
    # ==================================================================
    def _pipeline_put(self, bid, data, checksum, genstamp, targets):
        """
        PUT 第一个节点并让其链式转发（X-Forward-To）。
        返回 {"stored": [node_id...], "failed": [{node,error}]}
        """
        stored, failed = [], []
        if not targets:
            return {"stored": stored, "failed": failed}
        first = targets[0]
        rest = targets[1:]
        forward = [f"{self._node_url(t['node_id'])}/block/{bid}"
                   f"?genstamp={genstamp}&checksum={checksum}&size={len(data)}"
                   for t in rest]
        url = (f"{first['url'].rstrip('/')}/block/{bid}"
               f"?genstamp={genstamp}&checksum={checksum}&size={len(data)}")
        headers = {"X-Cluster-Key": self.cluster_key,
                   "Content-Type": "application/octet-stream"}
        if forward:
            headers["X-Forward-To"] = ",".join(forward)
        try:
            _s, _h, body = http_request(url, "PUT", data=data,
                                        headers=headers, timeout=30)
            resp = json.loads(body.decode("utf-8")) if body else {}
            stored.append(first["node_id"])

            def flatten(hops):
                """流水线应答是嵌套结构（dn1 -> dn2 -> dn3），递归展平。"""
                for hop in hops:
                    if hop.get("ok"):
                        if hop.get("node"):
                            stored.append(hop["node"])
                        flatten(hop.get("forwarded", []))
                    else:
                        failed.append(hop)

            flatten(resp.get("forwarded", []))
        except HttpError as e:
            failed.append({"node": first["node_id"], "error": str(e)[:200]})
        return {"stored": stored, "failed": failed}

    def _record_stored_replicas(self, bid, blk_genstamp, checksum, size,
                                stored_nodes):
        with self.meta.lock:
            blk = self.meta.get("blocks")["blocks"].get(bid)
            if not blk:
                return
            for nid in stored_nodes:
                if nid:
                    self._record_replica(bid, blk, nid, blk_genstamp,
                                         checksum, size, "ok")
            self.meta.touch("blocks")
        self.check_block_health(bid)

    def store_data_blocks(self, data, desired=None, author="system", path=None):
        """
        通用写入：bytes -> 分块 -> 去重 ->（命中加密域则逐块封包加密）->
        流水线复制 -> 返回块清单。
        （上传完成 / 合并写回 / 种子数据共用）

        加密在 NameNode 内完成：DataNode 收到并落盘的已是密文容器，
        其磁盘文件无法直接读出明文。
        """
        desired = desired or config.DEFAULT_REPLICATION
        content_hash = sha256_bytes(data)
        scope_path = self.keys.scope_of(path) if path else None
        chunks = chunking.chunk_bytes(data)
        block_ids = []
        dedup_hits = 0
        enc_blocks = 0
        for ch in chunks:
            bid = None
            blob = ch.data
            enc_kid = None
            if scope_path:
                kid, _key = self.keys.current_key(scope_path)
                bid = self.register_existing_encrypted(kid, ch.checksum)
                if bid:
                    block_ids.append(bid)
                    dedup_hits += 1
                    continue
                blob = self.keys.seal_for_path(path, ch.data)[0]
                enc_kid = kid
            else:
                bid = self.register_existing_checksum(ch.checksum)
                if bid:
                    block_ids.append(bid)
                    dedup_hits += 1
                    continue
            blob_checksum = sha256_bytes(blob)
            bid, gs = self.allocate_block(
                len(blob), blob_checksum, desired,
                plain_checksum=ch.checksum if enc_kid else None,
                plain_size=ch.length if enc_kid else None,
                enc_kid=enc_kid)
            targets = self.choose_targets(len(blob), desired)
            result = self._pipeline_put(bid, blob, blob_checksum, gs, targets)
            self._record_stored_replicas(bid, gs, blob_checksum, len(blob),
                                         result["stored"])
            if not result["stored"]:
                # 首节点就失败：标记块缺失，交给恢复队列重试
                self.check_block_health(bid)
                self.log_event("ERROR", "block", "pipeline_failed", bid,
                               author, json.dumps(result["failed"])[:400])
            block_ids.append(bid)
            if enc_kid:
                enc_blocks += 1
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            by_ck = blocks_doc.setdefault("by_checksum", {})
            by_pk = blocks_doc.setdefault("by_plain_kid", {})
            for ch, bid in zip(chunks, block_ids):
                blk = blocks_doc["blocks"].get(bid)
                if blk and blk.get("encrypted"):
                    by_pk.setdefault(
                        f"{blk['enc_kid']}|{blk['plain_checksum']}", bid)
                else:
                    by_ck.setdefault(ch.checksum, bid)
            self.meta.touch("blocks", flush=False)
        manifest = chunking.build_manifest(chunks, total_size=len(data),
                                           content_hash=content_hash)
        return {"block_ids": block_ids, "content_hash": content_hash,
                "manifest": manifest, "dedup_hits": dedup_hits,
                "encrypted": bool(scope_path), "enc_blocks": enc_blocks,
                "scope": scope_path}

    def write_file_internal(self, path, data, author="admin", mime=None,
                            owner=None):
        """
        写文件（内部 API）：确保父目录存在 -> 存块 -> 建/覆盖 inode。
        path 为完整文件路径；data 可以是 bytes 或 str（按 UTF-8 编码）。
        若 path 位于已启用加密的目录下，块在落盘前已被加密。
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        path = os.path.normpath(path).replace("\\", "/")
        if not path.startswith("/"):
            path = "/" + path
        dir_path = "/".join(path.split("/")[:-1]) or "/"
        name = path.split("/")[-1]
        mime = mime or guess_mime(name)
        with self.meta.lock:
            self.fs.mkdirs(dir_path, owner or author)
            result = self.store_data_blocks(data, author=author, path=path)
            inode = self.fs.create_file(dir_path, name, len(data),
                                        result["content_hash"],
                                        result["block_ids"], mime,
                                        owner or author)
        self._record_hourly("uploads", 1)
        self._record_hourly("bytes_in", len(data))
        return {"path": path, "inode_id": inode["id"],
                "size": len(data), "mime": mime,
                "content_hash": result["content_hash"],
                "block_ids": result["block_ids"],
                "chunks": len(result["block_ids"]),
                "dedup_hits": result["dedup_hits"],
                "encrypted": result["encrypted"], "scope": result["scope"]}

    # ==================================================================
    # 读路径（副本轮询 + 故障转移）
    # ==================================================================
    def read_blocks(self, block_ids, verify=True):
        """按块表顺序拼接读取（版本合并/预览/diff 使用）。"""
        out = []
        for bid in block_ids:
            data, _meta, _node = self.read_block(bid, verify=verify)
            out.append(data)
        return b"".join(out)

    def read_block(self, bid, start=None, end=None, verify=True,
                   use_cache=True):
        """
        读一个块：存活好副本轮询，校验失败自动切换下一副本。
        返回 (data, block_meta, served_by)。

        加密块：start/end 是**明文逻辑区间**。DataNode 只存密文容器，
        因此整块取回 -> NameNode 透明解密 -> 本地切片；
        解密后再与块表中的明文 sha256 比对（端到端完整性）。
        """
        if use_cache and start is None:
            cached = self.block_cache.get(bid)
            if cached is not None:
                return cached, self._block_meta(bid), "cache"
        with self.meta.lock:
            blk = self._block_meta(bid)
        if not blk:
            raise MissingBlockError(f"块表中不存在: {bid}")
        encrypted = bool(blk.get("encrypted"))
        # 加密块不把 Range 透给 DataNode（容器头部 + nonce 使得密文偏移不等于
        # 明文偏移）；整块密文取回后本地解密切片。
        fetch_range = None if encrypted else (start, end)
        want_slice = encrypted and start is not None
        candidates = self.live_good_replicas(blk)
        if not candidates:
            # 放宽：任何持有该块且存活的节点（读时校验兜底）
            live_ids = {n["node_id"] for n in self.live_nodes()}
            candidates = [nid for nid, r in (blk.get("replicas") or {}).items()
                          if nid in live_ids]
        if not candidates:
            raise MissingBlockError(
                f"块 {bid} 无可用副本（missing），文件暂不可读")
        # 轮询起点
        self._rr_counter += 1
        order = candidates[self._rr_counter % len(candidates):] + \
            candidates[:self._rr_counter % len(candidates)]
        errors = []
        for nid in order:
            url = f"{self._node_url(nid).rstrip('/')}/block/{bid}"
            headers = {"X-Cluster-Key": self.cluster_key}
            if fetch_range is not None:
                headers["Range"] = f"bytes={fetch_range[0]}-{fetch_range[1]}"
            try:
                _s, _h, blob = http_request(url, "GET", headers=headers,
                                            timeout=15)
                if encrypted:
                    # 密文容器：HMAC 认证 + 透明解密
                    from . import crypto as _crypto
                    if not _crypto.is_encrypted_blob(blob):
                        raise NNError("期望密文容器但读到裸数据")
                    data, info = self.keys.open_blob(blob)
                    if info.get("kid") != blk.get("enc_kid"):
                        raise NNError("密文 kid 与块表记录不一致")
                    if verify:
                        actual = sha256_bytes(data)
                        if actual != blk.get("plain_checksum"):
                            raise NNError("解密后明文校验和不匹配")
                    if want_slice:
                        data = data[start:end + 1]
                else:
                    data = blob
                    if verify and start is None:
                        actual = sha256_bytes(data)
                        if actual != blk["checksum"]:
                            raise NNError("校验和不匹配")
                if start is None and use_cache:
                    self.block_cache.put(bid, data)
                return data, blk, nid
            except Exception as e:  # noqa: BLE001
                errors.append(f"{nid}:{e}")
                # 通知该节点此副本可疑
                with self.meta.lock:
                    b2 = self.meta.get("blocks")["blocks"].get(bid)
                    if b2 and nid in b2.get("replicas", {}):
                        b2["replicas"][nid]["state"] = "corrupt"
                        self.meta.touch("blocks", flush=False)
                self.block_cache.invalidate(bid)
                self.check_block_health(bid)
                self.log_event("WARN", "block", "read_failover", bid, "system",
                               f"副本 {nid} 读取失败，切换下一副本: {e}")
        raise MissingBlockError(f"块 {bid} 所有副本读取失败: {errors}")

    def _block_meta(self, bid):
        blk = self.meta.get("blocks")["blocks"].get(bid)
        return dict(blk) if blk else None

    def read_file_range(self, path, offset=0, length=None, user=None):
        """
        文件级 Range 读：把 [offset, offset+length) 映射到块区间逐块读取。
        返回 (data, info)。
        """
        with self.meta.lock:
            inode = self.fs.resolve(path)
            if inode["type"] != "file":
                raise FsError(f"不是文件: {path}")
            block_ids = list(inode.get("block_ids", []))
            size = inode.get("size", 0)
        offset = max(0, min(offset, size))
        end = size - 1 if length is None else min(size - 1, offset + length - 1)
        if size == 0 or offset > end:
            return b"", {"size": size, "start": offset, "end": offset,
                         "nodes": [], "blocks_touched": 0}
        out = []
        nodes = []
        touched = 0
        pos = offset
        # 逐块定位（加密块用明文大小映射逻辑偏移）
        block_starts = []
        acc = 0
        with self.meta.lock:
            for bid in block_ids:
                blk = self._block_meta(bid)
                bsize = (blk or {}).get(
                    "plain_size", (blk or {}).get("size", 0))
                block_starts.append((bid, acc, bsize))
                acc += bsize
        for bid, bstart, bsize in block_starts:
            bend = bstart + bsize - 1
            if bend < pos or bstart > end:
                continue
            s = max(pos, bstart) - bstart
            e = min(end, bend) - bstart
            full = (s == 0 and e == bsize - 1)
            data, _blk, node = self.read_block(
                bid, None if full else s, None if full else e)
            out.append(data)
            nodes.append(node)
            touched += 1
        data = b"".join(out)
        # 热度记录
        self.record_access(path, "download", user, len(data),
                           nodes[0] if nodes else None)
        return data, {"size": size, "start": pos, "end": end,
                      "nodes": sorted(set(nodes)), "blocks_touched": touched}

    # ==================================================================
    # 上传会话（分块上传 + 断点续传）
    # ==================================================================
    def upload_begin(self, path, filename, size, session_id=None,
                     piece_size=None, user="anonymous"):
        with self.session_lock:
            self._prune_sessions_nolock()
            if session_id and session_id in self.sessions:
                sess = self.sessions[session_id]
                if sess["filename"] == filename and sess["size"] == size:
                    sess["last_active"] = now()
                    return self._session_view(sess)
            if len(self.sessions) >= config.UPLOAD_SESSION_MAX:
                raise NNError("上传会话过多，请稍后再试")
            sess_id = session_id or gen_id("up")
            stage_dir = os.path.join(config.SESSION_DIR, sess_id)
            os.makedirs(stage_dir, exist_ok=True)
            piece = piece_size or config.UPLOAD_PIECE_SIZE
            total_pieces = max(1, (size + piece - 1) // piece) if size else 1
            # 临时分片密钥：只保存在内存（不落盘、不入元数据）。
            # 即使分片暂存目录被直接查看，磁盘上也只有密文。
            from . import crypto as _crypto
            sess_key = _crypto.generate_key()
            sess = {
                "id": sess_id, "path": path, "filename": filename,
                "size": size, "piece_size": piece,
                "total_pieces": total_pieces,
                "received": {},            # idx -> {size, checksum, ts}
                "user": user, "created_at": now(), "last_active": now(),
                "stage_dir": stage_dir, "completed": False, "result": None,
                "sess_key": sess_key,
            }
            self.sessions[sess_id] = sess
        self.log_event("INFO", "upload", "begin", f"{path}/{filename}", user,
                       f"size={size} piece={piece} pieces={total_pieces}")
        return self._session_view(sess)

    def _session_view(self, sess):
        return {
            "session": sess["id"], "path": sess["path"],
            "filename": sess["filename"], "size": sess["size"],
            "piece_size": sess["piece_size"],
            "total_pieces": sess["total_pieces"],
            "received": sorted(int(i) for i in sess["received"]),
            "received_count": len(sess["received"]),
            "completed": sess["completed"],
            "created_at": sess["created_at"],
            "expires_in": max(0, sess["last_active"] +
                              config.UPLOAD_SESSION_TTL - now()),
        }

    def upload_chunk(self, session_id, index, data_b64, checksum=None,
                     simulate_fail=False):
        import base64
        from . import crypto as _crypto
        with self.session_lock:
            sess = self.sessions.get(session_id)
            if not sess:
                raise NNError("会话不存在或已过期")
            if sess["completed"]:
                raise NNError("会话已完成")
            sess_key = sess["sess_key"]
        # 混沌模式：服务端随机失败，演练前端重试
        flaky = simulate_fail or self.sim_chaos
        if flaky and random.random() < config.UPLOAD_FLAKY_RATE_CHAOS:
            raise NNError("模拟网络故障：分片写入失败（请重试）")
        try:
            data = base64.b64decode(data_b64)
        except Exception:
            raise NNError("分片 base64 解码失败")
        actual = sha256_bytes(data)
        if checksum and checksum != actual:
            raise NNError(f"分片 {index} 校验和不匹配，请重传")
        index = int(index)
        if index < 0 or index >= sess["total_pieces"]:
            raise NNError(f"非法分片序号: {index}")
        piece_path = os.path.join(sess["stage_dir"], f"piece_{index:06d}")
        from .util import atomic_write_bytes
        # 分片用会话临时密钥封包后原子落盘（kid 为会话 id）
        sealed = _crypto.seal_block(data, sess_key, f"sess:{session_id}")
        atomic_write_bytes(piece_path, sealed)
        with self.session_lock:
            sess["received"][str(index)] = {"size": len(data),
                                            "checksum": actual, "ts": now()}
            sess["last_active"] = now()
            done = len(sess["received"])
        return {"ok": True, "index": index, "checksum": actual,
                "received_count": done, "total_pieces": sess["total_pieces"],
                "complete": done == sess["total_pieces"]}

    def upload_complete(self, session_id, user="anonymous"):
        with self.session_lock:
            sess = self.sessions.get(session_id)
            if not sess:
                raise NNError("会话不存在或已过期")
            missing = [i for i in range(sess["total_pieces"])
                       if str(i) not in sess["received"]]
            if missing:
                raise NNError(f"仍有 {len(missing)} 个分片未上传: "
                              f"{missing[:10]}")
            if sess["completed"]:
                return sess["result"]
        # 读取全部分片（密文容器）-> 临时密钥透明解密 -> 拼接 -> 校验总大小
        from . import crypto as _crypto
        datas = []
        for i in range(sess["total_pieces"]):
            piece_path = os.path.join(sess["stage_dir"], f"piece_{i:06d}")
            with open(piece_path, "rb") as f:
                sealed = f.read()
            piece, _info = _crypto.open_block(
                sealed, lambda kid, _k=sess["sess_key"]: _k
                if kid == f"sess:{session_id}" else None)
            datas.append(piece)
        data = b"".join(datas)
        if sess["size"] and len(data) != sess["size"]:
            raise NNError(f"拼接后大小不符: {len(data)} != {sess['size']}")
        t0 = now()
        full_path = sess["path"].rstrip("/") + "/" + sess["filename"]
        info = self.write_file_internal(full_path, data, user)
        elapsed = now() - t0
        result = {
            "ok": True, "file": info, "elapsed_s": round(elapsed, 3),
            "throughput_mbps": round(len(data) / max(elapsed, 1e-6) / 1e6, 2),
            "pieces": sess["total_pieces"],
            "blocks": info["chunks"],
            "dedup_hits": info["dedup_hits"],
        }
        with self.session_lock:
            sess["completed"] = True
            sess["result"] = result
        self._cleanup_session_dir(sess)
        self.log_event("INFO", "upload", "complete", full_path, user,
                       f"{len(data)} 字节 / {sess['total_pieces']} 分片 / "
                       f"{info['chunks']} 块 / 去重命中 {info['dedup_hits']} / "
                       f"{result['elapsed_s']}s")
        self.emit("upload_complete",
                  f"{sess['filename']} 上传完成（{len(data)} B, "
                  f"{info['chunks']} 块）", path=full_path)
        return result

    def _cleanup_session_dir(self, sess):
        import shutil
        try:
            shutil.rmtree(sess["stage_dir"], ignore_errors=True)
        except Exception:
            pass

    def upload_status(self, session_id):
        with self.session_lock:
            sess = self.sessions.get(session_id)
            if not sess:
                raise NNError("会话不存在或已过期")
            return self._session_view(sess)

    def list_sessions(self):
        with self.session_lock:
            return [self._session_view(s) for s in self.sessions.values()]

    def _prune_sessions_nolock(self):
        t = now()
        for sid in [k for k, s in self.sessions.items()
                    if t - s["last_active"] > config.UPLOAD_SESSION_TTL]:
            sess = self.sessions.pop(sid)
            self._cleanup_session_dir(sess)

    def _session_gc_loop(self):
        while not self._stop.is_set():
            self._stop.wait(60)
            with self.session_lock:
                self._prune_sessions_nolock()

    # ==================================================================
    # 下载 / 预览 / 缩略图
    # ==================================================================
    def download_info(self, path):
        with self.meta.lock:
            inode = self.fs.resolve(path)
            if inode["type"] != "file":
                raise FsError(f"不是文件: {path}")
            blk_metas = [self._block_meta(b) for b in inode.get("block_ids", [])]
        scope = self.keys.scope_of(path)
        return {
            "path": path, "name": inode["name"], "size": inode.get("size", 0),
            "content_hash": inode.get("content_hash"),
            "mime": inode.get("mime"),
            "encrypted": bool(scope),
            "scope": scope,
            "encryption": ("落盘加密（DFSENC1）" if scope else None),
            "blocks": [{"id": b["id"], "size": b["size"],
                        "checksum": b["checksum"][:16],
                        "genstamp": b["genstamp"],
                        "encrypted": bool(b.get("encrypted")),
                        "kid": b.get("enc_kid"),
                        "replicas": sorted(b.get("replicas", {}).keys())}
                       for b in blk_metas if b],
        }

    def preview_file(self, path):
        with self.meta.lock:
            inode = self.fs.resolve(path)
            if inode["type"] != "file":
                raise FsError(f"不是文件: {path}")
            mime = inode.get("mime", "")
            size = inode.get("size", 0)
        data, info = self.read_file_range(
            path, 0, min(size, config.PREVIEW_MAX_BYTES))
        text = data.decode("utf-8", "replace") if not \
            (data[:8192].find(b"\x00") >= 0) else None
        return {"path": path, "mime": mime, "size": size,
                "truncated": size > len(data),
                "is_text": text is not None, "content": text,
                "nodes": info["nodes"]}

    def thumbnail(self, path):
        """图片文件读取原始字节作为缩略图（SVG/PNG 等浏览器自渲染）。"""
        with self.meta.lock:
            inode = self.fs.resolve(path)
            if inode["type"] != "file":
                raise FsError(f"不是文件: {path}")
            mime = inode.get("mime", "")
            size = inode.get("size", 0)
            if not mime.startswith("image/"):
                raise FsError("非图片文件")
            if size > config.THUMB_MAX_BYTES:
                raise FsError("图片过大，不生成缩略图")
        data, info = self.read_file_range(path, 0, size)
        self.record_access(path, "thumb", None, len(data),
                           info["nodes"][0] if info["nodes"] else None)
        return data, mime

    # ==================================================================
    # 热度 / 统计
    # ==================================================================
    def record_access(self, path, op, user, nbytes, node=None):
        entry = {"ts": now(), "path": path,
                 "op": canonical_access_op(op, config.ACCESS_OP_CANON),
                 "user": user or "",
                 "bytes": nbytes or 0, "node": node or ""}
        with self.meta.lock:
            stats = self.meta.get("stats")
            access = stats.setdefault("access", [])
            access.append(entry)
            if len(access) > config.ACCESS_LOG_CAP:
                stats["access"] = access[-config.ACCESS_LOG_CAP:]
            self.meta.touch("stats", flush=False)
        # inode 上的计数
        try:
            with self.meta.lock:
                inode = self.fs.resolve(path, must_exist=False)
                if inode and inode["type"] == "file":
                    inode["access_count"] = inode.get("access_count", 0) + 1
                    inode["last_access"] = now()
                    self.meta.touch("fs", flush=False)
        except FsError:
            pass

    def _record_hourly(self, key, amount):
        hour = hour_key(now(), config.STATS_HOUR_OFFSET)
        with self.meta.lock:
            hourly = self.meta.get("stats").setdefault("hourly", {})
            bucket = hourly.setdefault(hour, {"uploads": 0, "downloads": 0,
                                              "bytes_in": 0, "bytes_out": 0,
                                              "reads": 0})
            bucket[key] = bucket.get(key, 0) + amount
            self.meta.touch("stats", flush=False)

    def _stats_loop(self):
        while not self._stop.is_set():
            self._stop.wait(config.STATS_INTERVAL)
            try:
                self._append_capacity_history()
                self.meta.flush_dirty()
            except Exception:
                pass

    def _append_capacity_history(self):
        with self.node_lock:
            used = sum(n.get("storage", {}).get("used", 0)
                       for n in self.nodes.values())
            cap = sum(n.get("storage", {}).get("capacity", 0)
                      for n in self.nodes.values())
        with self.meta.lock:
            fs_stats = self.fs.global_stats()
            hist = self.meta.get("stats").setdefault("capacity_history", [])
            hist.append({"ts": now(), "used": used, "capacity": cap,
                         "files": fs_stats["files"],
                         "blocks": len(self.meta.get("blocks")["blocks"])})
            if len(hist) > config.CAPACITY_HISTORY_CAP:
                self.meta.get("stats")["capacity_history"] = \
                    hist[-config.CAPACITY_HISTORY_CAP:]
            self.meta.touch("stats", flush=False)

    def overview_stats(self):
        with self.meta.lock:
            blocks = list(self.meta.get("blocks")["blocks"].values())
            fs_stats = self.fs.global_stats()
            with self.health_lock:
                under = len(self.under_replicated)
                corrupt = len(self.corrupt_replicas)
                missing = len(self.missing_blocks)
        with self.node_lock:
            nodes = list(self.nodes.values())
        total_cap = sum(n.get("storage", {}).get("capacity", 0) for n in nodes)
        total_used = sum(n.get("storage", {}).get("used", 0) for n in nodes)
        rep_dist = {}
        size_hist = {}
        for blk in blocks:
            live = len(self.live_good_replicas(blk))
            rep_dist[str(live)] = rep_dist.get(str(live), 0) + 1
            bucket = chunking.size_bucket(blk.get("size", 0))
            size_hist[bucket] = size_hist.get(bucket, 0) + 1
        logical = fs_stats["bytes"]
        return {
            "files": fs_stats["files"],
            "dirs": fs_stats["dirs"],
            "logical_bytes": logical,
            "physical_bytes": total_used,
            "replication_overhead": round(total_used / logical, 2)
            if logical else 0,
            "blocks": len(blocks),
            "block_size_hist": size_hist,
            "replica_dist": rep_dist,
            "capacity": total_cap,
            "used": total_used,
            "free": max(0, total_cap - total_used),
            "nodes_total": len(nodes),
            "nodes_live": sum(1 for n in nodes if n["state"] == "LIVE"),
            "nodes_dead": sum(1 for n in nodes if n["state"] == "DEAD"),
            "under_replicated": under,
            "corrupt_replicas": corrupt,
            "missing_blocks": missing,
            "ext_bytes": fs_stats["ext_bytes"],
            "ext_count": fs_stats["ext_count"],
            "trash": self.fs.trash_stats(),
            "versions": self.versions.repo_stats(),
            "cache": self.block_cache.stats(),
            "api_rate": round(self.api_rate.rate(), 2),
            "nn_uptime": now() - self.started_at,
            "meta": {k: {"vv": v["vv"], "bytes": v["bytes"]}
                     for k, v in self.meta.stats()["docs"].items()},
            "meta_stats": {k: v for k, v in self.meta.stats().items()
                           if k != "docs"},
        }

    def hotness(self, limit=12):
        """指数衰减热度榜 + 每文件访问 sparkline。"""
        import math
        with self.meta.lock:
            access = list(self.meta.get("stats").get("access", []))
        t = now()
        hl = config.HOTNESS_DECAY_HALF_LIFE
        per_file = {}
        for e in access:
            if e.get("op") not in ("download", "preview", "thumb"):
                continue
            age = max(0.0, t - e["ts"])
            weight = 0.5 ** (age / hl)
            f = per_file.setdefault(e["path"], {
                "path": e["path"], "score": 0.0, "count": 0, "bytes": 0,
                "last": 0, "ops": {}, "buckets": [0] * 12})
            f["score"] += weight
            f["count"] += 1
            f["bytes"] += e.get("bytes", 0)
            f["last"] = max(f["last"], e["ts"])
            f["ops"][e["op"]] = f["ops"].get(e["op"], 0) + 1
            # 最近 12 个时间桶（按访问记录窗口均分）
            bucket = int(age // (config.HOTNESS_DECAY_HALF_LIFE / 2))
            if bucket < 12:
                f["buckets"][11 - bucket] += 1
        top = sorted(per_file.values(), key=lambda x: -x["score"])[:limit]
        for f in top:
            f["score"] = round(f["score"], 3)
        return top

    def timeline_stats(self, hours=24):
        import time as _time
        with self.meta.lock:
            hourly = dict(self.meta.get("stats").get("hourly", {}))
            hist = list(self.meta.get("stats").get("capacity_history", []))
        buckets = []
        base = int(now() // 3600) * 3600
        for i in range(hours - 1, -1, -1):
            ts = base - i * 3600
            key = _time.strftime("%Y-%m-%dT%H", _time.localtime(ts))
            b = hourly.get(key, {})
            buckets.append({"hour": key,
                            "uploads": b.get("uploads", 0),
                            "downloads": b.get("downloads", 0),
                            "bytes_in": b.get("bytes_in", 0),
                            "bytes_out": b.get("bytes_out", 0)})
        return {"hourly": buckets, "capacity_history": hist[-300:]}

    # ==================================================================
    # 节点视图 / 演练
    # ==================================================================
    def nodes_view(self):
        with self.node_lock:
            nodes = [dict(n) for n in self.nodes.values()]
        per_node_blocks = {n["node_id"]: 0 for n in nodes}
        per_node_bytes = {n["node_id"]: 0 for n in nodes}
        per_node_corrupt = {n["node_id"]: 0 for n in nodes}
        with self.meta.lock:
            blocks = list(self.meta.get("blocks")["blocks"].values())
        for blk in blocks:
            for nid, rep in list((blk.get("replicas") or {}).items()):
                if nid in per_node_blocks:
                    per_node_blocks[nid] += 1
                    per_node_bytes[nid] += rep.get("size", 0)
                    if rep.get("state") == "corrupt":
                        per_node_corrupt[nid] += 1
        out = []
        for n in sorted(nodes, key=lambda x: x["node_id"]):
            nid = n["node_id"]
            out.append({
                "node_id": nid, "rack": n.get("rack"), "url": n.get("url"),
                "state": n.get("state"), "registered_at": n.get("registered_at"),
                "last_seen": n.get("last_seen"),
                "last_seen_ago": now() - n.get("last_seen", 0),
                "last_report_at": n.get("last_report_at"),
                "hb_count": n.get("hb_count", 0),
                "deaths": n.get("deaths", 0),
                "dead_at": n.get("dead_at"),
                "storage": n.get("storage", {}),
                "io": n.get("io", {}), "rates": n.get("rates", {}),
                "uptime": n.get("uptime", 0),
                "vv": n.get("vv", {}), "doc_vv": n.get("doc_vv", {}),
                "nn_block_count": per_node_blocks.get(nid, 0),
                "nn_block_bytes": per_node_bytes.get(nid, 0),
                "corrupt": per_node_corrupt.get(nid, 0),
                "pending_commands": len(self.pending_commands.get(nid, [])),
            })
        with self.health_lock:
            health = {
                "under_replicated": len(self.under_replicated),
                "corrupt_replicas": len(self.corrupt_replicas),
                "missing_blocks": len(self.missing_blocks),
                "scheduled": len(self.scheduled),
            }
        return {"nodes": out, "health": health,
                "summary": {
                    "total": len(out),
                    "live": sum(1 for n in out if n["state"] == "LIVE"),
                    "suspect": sum(1 for n in out if n["state"] == "SUSPECT"),
                    "dead": sum(1 for n in out if n["state"] == "DEAD"),
                }}

    def node_blocks(self, node_id, limit=200, offset=0):
        """从 DataNode 实时拉取其块清单（HTTP 同步演示）。"""
        dn = self.local_datanodes.get(node_id)
        if dn:
            return dn.block_list(limit, offset)
        # 远程节点：走块表反查
        with self.meta.lock:
            blocks = self.meta.get("blocks")["blocks"]
            items = [(bid, b) for bid, b in blocks.items()
                     if node_id in (b.get("replicas") or {})]
        total = len(items)
        out = []
        for bid, b in items[offset:offset + limit]:
            rep = b["replicas"][node_id]
            out.append({"id": bid, "genstamp": rep["genstamp"],
                        "size": rep["size"], "state": rep["state"],
                        "checksum": rep["checksum"][:16],
                        "stored_at": rep.get("updated_at")})
        return {"total": total, "blocks": out}

    def replica_matrix(self, limit=60):
        """块 x 节点 副本分布矩阵（节点页可视化）。"""
        with self.node_lock:
            node_ids = sorted(self.nodes.keys())
            live_ids = {nid for nid, n in self.nodes.items()
                        if n["state"] == "LIVE"}
        with self.meta.lock:
            blocks = dict(self.meta.get("blocks")["blocks"])

        def good_count(blk):
            n = 0
            for nid, rep in (blk.get("replicas") or {}).items():
                if nid in live_ids and rep.get("state") == "ok" and \
                        rep.get("genstamp", 0) == blk.get("genstamp", 0):
                    n += 1
            return n

        # 优先展示有问题的块
        def blk_score(bid_b):
            bid, blk = bid_b
            return (good_count(blk) - blk.get("desired", 3),
                    -len(blk.get("replicas", {})))

        items = sorted(blocks.items(), key=blk_score)[:limit]
        rows = []
        for bid, blk in items:
            cells = {}
            for nid in node_ids:
                rep = (blk.get("replicas") or {}).get(nid)
                if not rep:
                    cells[nid] = "-"
                elif rep.get("state") == "ok" and \
                        rep.get("genstamp") == blk.get("genstamp"):
                    cells[nid] = "ok"
                elif rep.get("state") == "corrupt":
                    cells[nid] = "corrupt"
                else:
                    cells[nid] = "stale"
            live = good_count(blk)
            rows.append({"block": bid, "short": short_hash(bid.replace("blk_", ""), 8),
                         "size": blk.get("size", 0),
                         "desired": blk.get("desired"),
                         "live": live, "cells": cells,
                         "status": ("missing" if live == 0 else
                                    "under" if live < blk.get("desired", 3)
                                    else "ok")})
        return {"nodes": node_ids, "rows": rows, "total_blocks": len(blocks)}

    def health_queue(self):
        with self.health_lock:
            under = dict(self.under_replicated)
            corrupt = {f"{b}@{n}": dict(v) for (b, n), v
                       in self.corrupt_replicas.items()}
            missing = set(self.missing_blocks)
            scheduled = dict(self.scheduled)
        with self.meta.lock:
            blocks = self.meta.get("blocks")["blocks"]
            under_items = []
            for bid, info in list(under.items())[:80]:
                blk = blocks.get(bid, {})
                under_items.append({
                    "block": bid, "desired": blk.get("desired"),
                    "live": len(self.live_good_replicas(blk)) if blk else 0,
                    "since": info["since"], "attempts": info.get("attempts", 0),
                    "scheduled": scheduled.get(bid),
                    "size": blk.get("size", 0),
                })
        return {"under_replicated": under_items, "corrupt": corrupt,
                "missing": sorted(missing)[:80],
                "counts": {"under": len(under), "corrupt": len(corrupt),
                           "missing": len(missing),
                           "scheduled": len(scheduled)}}

    # ---- 演练 ----
    def sim_kill_node(self, node_id):
        dn = self.local_datanodes.get(node_id)
        if not dn:
            raise NNError(f"节点不在本进程管理内: {node_id}")
        dn.kill_sim()
        with self.node_lock:
            n = self.nodes.get(node_id)
            if n:
                n["killed_flag"] = True
        self.log_event("WARN", "sim", "kill_node", node_id, "admin",
                       "故障演练：手动杀死节点")
        self.emit("sim_kill", f"演练：节点 {node_id} 已被杀死", node=node_id)
        return {"ok": True}

    def sim_revive_node(self, node_id):
        dn = self.local_datanodes.get(node_id)
        if not dn:
            raise NNError(f"节点不在本进程管理内: {node_id}")
        dn.revive_sim()
        self.log_event("INFO", "sim", "revive_node", node_id, "admin",
                       "故障演练：节点复活")
        self.emit("sim_revive", f"演练：节点 {node_id} 已复活", node=node_id)
        return {"ok": True}

    def sim_corrupt_block(self, block_id, node_id):
        with self.meta.lock:
            blk = self.meta.get("blocks")["blocks"].get(block_id)
        if not blk:
            raise NNError(f"块不存在: {block_id}")
        if node_id not in (blk.get("replicas") or {}):
            raise NNError(f"{node_id} 上没有块 {block_id} 的副本")
        dn = self.local_datanodes.get(node_id)
        if not dn:
            raise NNError(f"节点不在本进程管理内: {node_id}")
        dn.corrupt_block_sim(block_id)
        self.log_event("WARN", "sim", "corrupt_block",
                       f"{block_id}@{node_id}", "admin",
                       "故障演练：注入静默数据损坏（等待巡检/读取发现）")
        self.emit("sim_corrupt",
                  f"演练：块 {short_hash(block_id, 12)}@{node_id} 已注入损坏",
                  node=node_id, block=block_id)
        return {"ok": True}

    def sim_chaos_mode(self, enabled):
        self.sim_chaos = bool(enabled)
        self.log_event("WARN", "sim", "chaos_mode", str(enabled), "admin", "")
        return {"ok": True, "enabled": self.sim_chaos}

    # ==================================================================
    # GC（版本树保护下的块回收）
    # ==================================================================
    def referenced_blocks(self):
        refs = set()
        with self.meta.lock:
            for _p, inode in self.fs.all_files():
                refs.update(inode.get("block_ids", []))
            trash_root = self.fs.get_inode(self.fs.trash_id)
            if trash_root:
                stack = list(trash_root.get("children", []))
                inodes = self.fs._inodes()
                while stack:
                    cur = stack.pop()
                    node = inodes.get(cur)
                    if not node:
                        continue
                    refs.update(node.get("block_ids", []))
                    stack.extend(node.get("children", []))
        refs |= self.versions.all_referenced_blocks()
        with self.session_lock:
            for sess in self.sessions.values():
                refs.update(sess.get("result", {}).get("file", {})
                            .get("block_ids", []) if sess.get("result") else [])
        return refs

    def gc_blocks(self):
        """回收未被引用的块（宽限期防止误删刚写的块）。"""
        refs = self.referenced_blocks()
        t = now()
        deleted = 0
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            blocks = blocks_doc["blocks"]
            by_ck = blocks_doc.get("by_checksum", {})
            by_pk = blocks_doc.get("by_plain_kid", {})
            to_delete = []
            for bid, blk in blocks.items():
                if bid in refs:
                    continue
                if t - blk.get("created_at", t) < config.GC_GRACE_SECONDS:
                    continue
                to_delete.append(bid)
            for bid in to_delete:
                blk = blocks.pop(bid)
                ck = blk.get("checksum")
                if by_ck.get(ck) == bid:
                    by_ck.pop(ck, None)
                if blk.get("encrypted"):
                    pk = f"{blk.get('enc_kid')}|{blk.get('plain_checksum')}"
                    if by_pk.get(pk) == bid:
                        by_pk.pop(pk, None)
                for nid in (blk.get("replicas") or {}):
                    self._enqueue_command(nid, {
                        "type": "delete", "block_id": bid,
                        "reason": "GC：无引用的孤儿块"})
                deleted += 1
                with self.health_lock:
                    self.under_replicated.pop(bid, None)
                    self.missing_blocks.discard(bid)
            if deleted:
                self.meta.touch("blocks")
        if deleted:
            self.log_event("INFO", "gc", "gc_blocks", "", "system",
                           f"回收 {deleted} 个未引用块")
        return deleted

    def _gc_loop(self):
        while not self._stop.is_set():
            self._stop.wait(config.GC_INTERVAL)
            try:
                self.gc_blocks()
            except Exception as e:  # noqa: BLE001
                self.log_event("ERROR", "gc", "loop_error", "", "system", str(e))

    def _trash_loop(self):
        while not self._stop.is_set():
            self._stop.wait(config.TRASH_EXPIRE_CHECK_INTERVAL)
            try:
                expired, freed = self.fs.purge_expired()
                if expired:
                    self.log_event("INFO", "fs", "trash_expire", "", "system",
                                   f"回收站过期清理 {len(expired)} 项（单位 "
                                   f"{config.TRASH_RETENTION_UNIT}），"
                                   f"释放 {len(freed)} 个块引用")
            except Exception:
                pass

    # ==================================================================
    # 块详情（文件详情页：块 -> 副本 -> 节点）
    # ==================================================================
    def file_blocks_detail(self, path):
        with self.meta.lock:
            inode = self.fs.resolve(path)
            if inode["type"] != "file":
                raise FsError(f"不是文件: {path}")
            out = []
            for bid in inode.get("block_ids", []):
                blk = self._block_meta(bid)
                if not blk:
                    out.append({"id": bid, "missing": True})
                    continue
                live = self.live_good_replicas(blk)
                out.append({
                    "id": bid,
                    "short": short_hash(bid.replace("blk_", ""), 8),
                    "size": blk["size"],
                    "plain_size": blk.get("plain_size", blk["size"]),
                    "checksum": blk["checksum"][:16],
                    "genstamp": blk["genstamp"],
                    "desired": blk.get("desired"),
                    "encrypted": bool(blk.get("encrypted")),
                    "kid": blk.get("enc_kid"),
                    "live": len(live),
                    "status": ("missing" if not live else
                               "under" if len(live) < blk.get("desired", 3)
                               else "ok"),
                    "replicas": [
                        {"node": nid, "state": r.get("state"),
                         "genstamp": r.get("genstamp"),
                         "size": r.get("size"),
                         "updated_at": r.get("updated_at"),
                         "rack": (self.nodes.get(nid) or {}).get("rack"),
                         "live": nid in {n["node_id"] for n in self.live_nodes()}}
                        for nid, r in sorted((blk.get("replicas") or {}).items())],
                })
            return {"path": path, "size": inode.get("size", 0),
                    "content_hash": inode.get("content_hash"),
                    "blocks": out}

    def block_paths(self, bid):
        """反查引用某块的文件路径（节点页/健康队列展示用）。"""
        with self.meta.lock:
            paths = [p for p, inode in self.fs.all_files()
                     if bid in inode.get("block_ids", [])]
        return paths

    def reencrypt_path(self, path, author="admin"):
        """
        把已启用加密目录下的存量文件用**当前密钥**重新加密落盘
        （读取透明解密旧块/明文块 -> 以新密文块重写 inode 引用）。
        仅处理位于某加密域内、且尚有明文块的文件；已是密文且 kid 为当前
        密钥版本的文件跳过（幂等）。
        """
        scope_path = self.keys.scope_of(path)
        if not scope_path:
            raise NNError(f"路径不在加密目录内: {path}")
        kid, _key = self.keys.current_key(scope_path)
        rewritten = skipped = failed = 0
        retained_history = 0
        for fpath, inode in self.fs.all_files():
            if not (fpath == scope_path
                    or fpath.startswith(scope_path.rstrip("/") + "/")):
                continue
            bids = inode.get("block_ids", [])
            with self.meta.lock:
                metas = [self._block_meta(b) for b in bids]
            needs = any((not m) or (not m.get("encrypted"))
                        or m.get("enc_kid") != kid for m in metas)
            if not needs:
                skipped += 1
                continue
            try:
                data = self.read_blocks(bids)
                # 先记录旧块（可能是明文块），重写成功后立即安全擦除，
                # 不等待 GC 宽限期——敏感数据一旦被密文替换就不应在盘上残留。
                info = self.write_file_internal(
                    fpath, data, inode.get("owner", author),
                    mime=inode.get("mime"))
                old_bids = [b for b in bids if b not in info["block_ids"]]
                # 但仍被历史提交/回收站/会话引用的旧块必须保留——
                # 任何一份历史版本都不能因加密而失效。
                refs = self.referenced_blocks()
                purgeable = [b for b in old_bids if b not in refs]
                retained_history += len(old_bids) - len(purgeable)
                self.purge_blocks_immediate(purgeable)
                rewritten += 1
                self.log_event("INFO", "crypto", "reencrypt_file", fpath,
                               author,
                               f"用密钥 {kid} 重新加密（{info['chunks']} 块），"
                               f"立即擦除无引用旧块 {len(purgeable)} 个"
                               + (f"，保留历史版本块 {len(old_bids)-len(purgeable)} 个"
                                  if len(old_bids) != len(purgeable) else ""))
            except Exception as e:  # noqa: BLE001
                failed += 1
                self.log_event("ERROR", "crypto", "reencrypt_failed", fpath,
                               author, str(e)[:200])
        return {"scope": scope_path, "kid": kid, "rewritten": rewritten,
                "skipped": skipped, "failed": failed,
                "retained_history_blocks": retained_history}

    def purge_blocks_immediate(self, bids):
        """
        立即从块表删除并命令所有持有节点擦除这些块（绕过 GC 宽限期）。
        用于重加密替换：旧明文块不应在磁盘上有任何宽限残留。
        """
        if not bids:
            return 0
        deleted = 0
        with self.meta.lock:
            blocks_doc = self.meta.get("blocks")
            blocks = blocks_doc["blocks"]
            by_ck = blocks_doc.get("by_checksum", {})
            by_pk = blocks_doc.get("by_plain_kid", {})
            for bid in bids:
                blk = blocks.pop(bid, None)
                if not blk:
                    continue
                deleted += 1
                ck = blk.get("checksum")
                if by_ck.get(ck) == bid:
                    by_ck.pop(ck, None)
                if blk.get("encrypted"):
                    pk = f"{blk.get('enc_kid')}|{blk.get('plain_checksum')}"
                    if by_pk.get(pk) == bid:
                        by_pk.pop(pk, None)
                for nid in (blk.get("replicas") or {}):
                    self._enqueue_command(nid, {
                        "type": "delete", "block_id": bid,
                        "reason": "重加密：旧块立即安全擦除"})
                with self.health_lock:
                    self.under_replicated.pop(bid, None)
                    self.missing_blocks.discard(bid)
            if deleted:
                self.meta.touch("blocks")
        return deleted

    # ==================================================================
    # 落盘加密验证（证明 DataNode 磁盘上确实不是明文）
    # ==================================================================
    def _raw_block_from_datanode(self, bid, nid):
        """绕过 NameNode 解密，直接从 DataNode 取原始落盘字节。"""
        url = f"{self._node_url(nid).rstrip('/')}/block/{bid}"
        _s, _h, blob = http_request(
            url, "GET", headers={"X-Cluster-Key": self.cluster_key},
            timeout=15)
        return blob

    def verify_file_encryption(self, path):
        """
        对文件逐块做"落盘即密文"核验：
          * 直接读 DataNode 上的原始字节（不经过 NameNode 解密层）；
          * 期望看到 DFSENC1 容器（加密块）——且原始字节中不含明文特征串；
          * 用对应密钥版本能成功通过 HMAC 认证并解出与文件一致的明文；
          * 同一逻辑块的各副本原始字节逐字节一致（密文副本一致）。
        未启用加密目录下的文件返回 encrypted=false（本就以明文存储）。
        """
        from . import crypto as _crypto
        with self.meta.lock:
            inode = self.fs.resolve(path)
            if inode["type"] != "file":
                raise FsError(f"不是文件: {path}")
            block_ids = list(inode.get("block_ids", []))
            file_hash = inode.get("content_hash")
            scope_path = self.keys.scope_of(path)
            blk_infos = [self._block_meta(b) for b in block_ids]
        if not scope_path:
            return {"path": path, "encrypted": False,
                    "scope": None,
                    "note": "该文件不在任何已启用加密的目录下，按明文存储"}
        checks = []
        plain_pieces = []
        all_ok = True
        leak_findings = []
        for idx, (bid, blk) in enumerate(zip(block_ids, blk_infos)):
            if not blk:
                all_ok = False
                checks.append({"index": idx, "block": bid, "ok": False,
                               "error": "块表中不存在该块"})
                continue
            reps = self.live_good_replicas(blk)
            if not reps:
                reps = [nid for nid in (blk.get("replicas") or {})]
            item = {"index": idx, "block": bid,
                    "short": short_hash(bid.replace("blk_", ""), 8),
                    "kid": blk.get("enc_kid"),
                    "cipher_bytes": blk.get("size", 0),
                    "plain_bytes": blk.get("plain_size", 0),
                    "replicas_checked": [], "ok": True, "problems": []}
            raw_blobs = {}
            probe = os.path.basename(path).encode("utf-8")
            for nid in reps:
                try:
                    blob = self._raw_block_from_datanode(bid, nid)
                    raw_blobs[nid] = blob
                    is_enc = _crypto.is_encrypted_blob(blob)
                    rep_info = {"node": nid, "bytes": len(blob),
                                "container": is_enc, "ok": is_enc}
                    if not is_enc:
                        rep_info["ok"] = False
                        item["problems"].append(f"{nid}: 磁盘上不是密文容器")
                    elif probe and probe in blob:
                        # 密文容器里不应直接出现文件名等明文特征
                        rep_info["ok"] = False
                        item["problems"].append(
                            f"{nid}: 密文中检出明文特征串（疑似泄露）")
                        leak_findings.append(
                            f"{item['short']}@{nid} 命中文件名特征")
                    item["replicas_checked"].append(rep_info)
                except Exception as e:  # noqa: BLE001
                    item["ok"] = False
                    item["problems"].append(f"取样失败 {nid}: {e}")
                    item["replicas_checked"].append(
                        {"node": nid, "ok": False, "error": str(e)[:120]})
            # 副本一致性 + 解密正确性（取任一副本验证）
            if raw_blobs:
                first_nid, first_blob = next(iter(raw_blobs.items()))
                for nid, blob in raw_blobs.items():
                    if blob != first_blob:
                        item["ok"] = False
                        item["problems"].append(
                            f"副本 {nid} 与 {first_nid} 的密文字节不一致")
                try:
                    plain, info = self.keys.open_blob(first_blob)
                    if sha256_bytes(plain) != blk.get("plain_checksum"):
                        item["ok"] = False
                        item["problems"].append("解密后明文校验和不匹配")
                    else:
                        item["decrypt_ok"] = True
                        plain_pieces.append(plain)
                except Exception as e:  # noqa: BLE001
                    item["ok"] = False
                    item["problems"].append(f"解密/认证失败: {e}")
            else:
                item["ok"] = False
                item["problems"].append("没有可取样的存活副本")
            if not item["ok"]:
                all_ok = False
            checks.append(item)
        content_ok = None
        if plain_pieces and len(plain_pieces) == len(block_ids):
            content_ok = sha256_bytes(b"".join(plain_pieces)) == file_hash
        return {
            "path": path, "encrypted": True, "scope": scope_path,
            "algorithm": "HMAC-SHA256-CTR / DFSENC1 容器",
            "all_ok": all_ok and content_ok is not False
            and not leak_findings,
            "content_roundtrip_ok": content_ok,
            "leak_findings": leak_findings,
            "blocks": checks,
            "checked_at": now(),
        }
