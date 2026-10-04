"""Validate a complete restore plan, then commit or roll back every file."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading

STORAGE_LOCK = threading.RLock()


def validate_modules(payload, known):
    version = payload.get("schema_version", payload.get("_version", 1))
    if type(version) is not int or version not in (1, 2):
        raise ValueError("不支持的备份 schema 版本")
    for key in set(known) | {"credentials"}:
        value = payload.get(key)
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"备份模块 {key} 必须为对象")
    credentials = payload.get("credentials") or {}
    if any(not isinstance(v, str) for k, v in credentials.items() if k in {"iptv_password", "epg_des3_key"}):
        raise ValueError("凭据字段必须为字符串")
    subscription = payload.get("subscription_candidates") or {}
    ids = subscription.get("candidate_ids", [])
    if not isinstance(ids, list) or any(not isinstance(v, str) for v in ids):
        raise ValueError("订阅候选列表必须为字符串数组")
    for key in ("channels", "operator_channels", "discovered_channels", "fcc", "channel_snapshots"):
        if any(not isinstance(v, dict) for v in (payload.get(key) or {}).values()):
            raise ValueError(f"备份模块 {key} 的记录必须为对象")


class RestoreTransaction:
    """Stage alongside the destination volume; keep private originals on disk.

    Handles synchronous write failures. A failed rollback retains its journal
    for manual recovery; it is never silently reported as a successful import.
    """
    def __init__(self, root):
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=".restore-", dir=root))
        self.entries = {}

    def stage(self, target, content):
        target = Path(target)
        staged = self.directory / f"new-{len(self.entries)}"
        with staged.open("xb") as out:
            os.chmod(staged, 0o600)
            if isinstance(content, bytes):
                out.write(content)
            else:
                shutil.copyfileobj(content, out, 1024*1024)
            out.flush()
            os.fsync(out.fileno())
        self.entries[target] = staged

    def stage_json(self, target, value):
        self.stage(target, (json.dumps(value, ensure_ascii=False, indent=2)+"\n").encode())

    def commit(self):
        originals, written = {}, []
        with STORAGE_LOCK:
            try:
                for index, target in enumerate(self.entries):
                    if target.exists():
                        original = self.directory / f"old-{index}"
                        shutil.copy2(target, original)
                        os.chmod(original, 0o600)
                        originals[target] = original
                    else:
                        originals[target] = None
                (self.directory / "journal.json").write_text(json.dumps(
                    {str(k): str(v) if v else None for k,v in originals.items()}))
                for target, staged in self.entries.items():
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    os.replace(staged, target)
                    written.append(target)
            except Exception:
                failures = []
                for target in reversed(written):
                    try:
                        if originals[target]:
                            os.replace(originals[target], target)
                        else:
                            target.unlink(missing_ok=True)
                    except OSError:
                        failures.append(str(target))
                if failures:
                    raise RuntimeError(f"恢复失败且回滚未完成；保留恢复日志于 {self.directory}") from None
                shutil.rmtree(self.directory)
                raise
        shutil.rmtree(self.directory)

    def abort(self):
        shutil.rmtree(self.directory, ignore_errors=True)


def restore_modules(payload, selected_keys, *, files, root, settings_store, epg_key_store,
                    credential_keys, validate_settings, transaction=None):
    """Build one validated restore plan for JSON state and optional staged archives."""
    validate_modules(payload, [key for key, _ in files])
    tx = transaction or RestoreTransaction(root)
    restored, skipped = [], []
    try:
        # Compose settings once so restoring public settings cannot erase secrets.
        settings = settings_store.load()
        for key, path in files:
            if key not in selected_keys:
                continue
            value = payload.get(key)
            if value is None:
                skipped.append(key)
                continue
            if key == "settings":
                value = {k:v for k,v in value.items() if k not in credential_keys}
                validate_settings(value)
                settings.update(value)
            else:
                tx.stage_json(path, value)
            restored.append(key)
        if "credentials" in selected_keys:
            credentials = payload.get("credentials")
            if credentials is None:
                skipped.append("credentials")
            else:
                if "iptv_password" in credentials:
                    settings["iptv_password"] = credentials["iptv_password"]
                if "epg_des3_key" in credentials:
                    tx.stage_json(epg_key_store.path, {"epg_des3_key": credentials["epg_des3_key"].strip()})
                restored.append("credentials")
        if "settings" in restored or "credentials" in restored:
            tx.stage_json(settings_store.path, settings)
        tx.commit()
    except Exception:
        # commit preserves a journal when rollback itself fails.
        if not (tx.directory / "journal.json").exists():
            tx.abort()
        raise
    return restored, skipped
