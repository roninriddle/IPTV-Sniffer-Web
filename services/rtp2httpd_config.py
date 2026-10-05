"""Read rtp2httpd INI/UCI without executing shell or router configuration."""
import re
import shlex


def parse_config(text):
    is_uci = any(re.match(r"\s*config\s+", line) for line in text.splitlines())
    values, binds, instances = {}, [], []
    section = "global"
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if is_uci:
            # UCI quotes protect spaces, URL fragments and comment characters.
            tokens = shlex.split(line, comments=True, posix=True)
            if not tokens:
                continue
            if tokens[0] == "config":
                if len(tokens) not in (2, 3):
                    raise ValueError("UCI config 段格式不正确")
                current = {"type": tokens[1], "name": tokens[2] if len(tokens) == 3 else tokens[1],
                           "values": {}, "bind": []}
                instances.append(current)
            elif tokens[0] in ("option", "list"):
                if current is None or len(tokens) < 2:
                    raise ValueError("UCI 选项必须位于 config 段内")
                args = tokens[1:]
                if "=" in args[0]:
                    key, value = args[0].split("=", 1)
                    if len(args) != 1:
                        raise ValueError("UCI 选项包含多余参数")
                else:
                    if len(args) > 2:
                        raise ValueError("UCI 选项包含多余参数，请给值加引号")
                    key, value = args[0], args[1] if len(args) == 2 else ""
                key = key.replace("_", "-")
                if tokens[0] == "list":
                    if key == "listen" and value:
                        current["bind"].append(value)
                else:
                    current["values"][key] = value
            else:
                raise ValueError("不支持的 UCI 配置语法")
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip() or "global"
        elif section == "bind" and "=" not in line:
            binds.append(line)
        elif "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.split("#", 1)[0].split(";", 1)[0].strip()
            if key:
                values[f"{section}.{key}"] = value
                values.setdefault(key, value)
    if is_uci:
        for instance in instances:
            for key, value in instance["values"].items():
                values[f"{instance['name']}.{key}"] = value
                values.setdefault(key, value)
            binds.extend(instance["bind"])
    return {"values": values, "bind": binds, "format": "uci" if is_uci else "ini", "instances": instances}


def effective_config(parsed):
    if parsed["format"] != "uci":
        return parsed
    def flag(value):
        value = str(value).lower()
        if value not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
            raise ValueError("UCI 布尔选项无效")
        return value in {"1", "true", "yes", "on"}
    active = [i for i in parsed["instances"] if i["type"] in {"instance", "rtp2httpd"}
              and not flag(i["values"].get("disabled", "0")) and flag(i["values"].get("enabled", "1"))]
    if len(active) != 1:
        raise ValueError("UCI 未找到唯一启用实例，请提供目标实例的独立配置文件")
    instance = active[0]
    values = dict(instance["values"])
    if flag(values.get("use-config-file", "0")):
        raise ValueError("UCI 实例启用了外部配置文件，请挂载并选择实际的 rtp2httpd.conf")
    if instance["type"] == "rtp2httpd" or "advanced-interface-settings" in values:
        if flag(values.get("advanced-interface-settings", "0")):
            values.pop("upstream-interface", None)
        else:
            for suffix in ("multicast", "fcc", "rtsp", "http"):
                values.pop(f"upstream-interface-{suffix}", None)
    return {**parsed, "values": values, "bind": instance["bind"], "instance": instance["name"]}
