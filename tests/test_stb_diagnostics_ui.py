"""STB 捕获诊断的前端渲染。

后端 `diagnostics` 已经给出采集侧的原始计数，但界面上只有一句
「未发现频道」。用户据此无法判断问题出在哪一环：是没抓到包、
抓到了但没匹配到机顶盒、还是匹配到了却没解析出频道表。

这里验证两件事：
1. 页面与脚本具备渲染诊断的契约（容器、调用点、字段标签）；
2. 结论生成的分支覆盖了每一级断点，而不是所有情况都返回同一句话。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_JS = PROJECT_ROOT / "static" / "app.js"
INDEX_HTML = PROJECT_ROOT / "templates" / "index.html"

NODE = shutil.which("node")

requires_node = pytest.mark.skipif(NODE is None, reason="需要 node 才能执行前端逻辑")


def _extract_function(name: str) -> str:
    """按大括号配平从 app.js 里取出指定函数源码。

    直接用正则截取会在嵌套对象字面量上截断，所以这里做一次配平扫描。
    """
    source = APP_JS.read_text(encoding="utf-8")
    start = source.find(f"function {name}(")
    assert start >= 0, f"app.js 缺少 {name}()"
    index = source.index("{", start)
    depth = 0
    for pos in range(index, len(source)):
        char = source[pos]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : pos + 1]
    raise AssertionError(f"{name}() 的大括号未闭合")


def _run_conclusions(diag: dict) -> list[str]:
    """在 node 里跑一遍 stbDiagnosticsConclusions，返回结论文本。"""
    script = (
        f"{_extract_function('escapeHtml')}\n"
        f"{_extract_function('formatBytes')}\n"
        f"{_extract_function('stbDiagnosticsConclusions')}\n"
        f"console.log(JSON.stringify(stbDiagnosticsConclusions({json.dumps(diag)})));"
    )
    result = subprocess.run(
        [NODE, "-e", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


class TestDiagnosticsMarkup:
    """页面必须提供诊断容器，否则后端字段无处可显示。"""

    def test_page_exposes_diagnostics_container(self):
        page = INDEX_HTML.read_text(encoding="utf-8")

        assert 'id="stbDiscoveryDiagnostics"' in page
        assert 'id="stbDiscoveryDiagBody"' in page
        assert 'id="stbDiscoveryDiagConclusion"' in page

    def test_container_starts_hidden(self):
        """未捕获时不该展示一块空白诊断区。"""
        page = INDEX_HTML.read_text(encoding="utf-8")

        assert re.search(r'<details id="stbDiscoveryDiagnostics"[^>]*\bhidden\b', page)

    def test_status_render_invokes_diagnostics(self):
        """每次状态刷新都要重绘诊断，否则停止后看到的仍是上一轮结果。"""
        script = APP_JS.read_text(encoding="utf-8")
        status_fn = _extract_function("renderStbDiscoveryStatus")

        assert "renderStbDiscoveryDiagnostics(state)" in status_fn

    def test_every_diagnostics_field_has_a_label(self):
        """后端提供的每个字段都要有中文标签，避免裸key 暴露给用户。"""
        script = APP_JS.read_text(encoding="utf-8")

        for label in ("抓包大小", "TCP 流", "匹配响应流", "解析出频道"):
            assert label in script, f"缺少诊断字段标签：{label}"


class TestDiagnosticsConclusions:
    """结论必须随断点变化，且落到可执行的下一步。"""

    @requires_node
    def test_header_only_is_not_treated_as_captured_packets(self):
        notes = _run_conclusions({"pcap_size": 24, "packet_count": 0})
        assert "没有捕获到完整数据包" in notes[0]

    @requires_node
    def test_mac_only_waits_for_proven_ip(self):
        notes = _run_conclusions({"pcap_size": 400, "packet_count": 1, "identity_source": "unresolved"})
        assert "DHCP ACK" in notes[0]

    @requires_node
    def test_unknown_mac_statistics_do_not_claim_missing_mac(self):
        html = "".join(_run_render_rows({"pcap_size": 1024, "mac_requested": "02:00:00:00:00:20",
                                        "mac_supported": False, "mac_not_seen": False}))
        assert "无法判断" in html
        assert "该 MAC 出现次数" not in html

    @requires_node
    def test_empty_capture_blames_the_capture_setup(self):
        notes = _run_conclusions({"pcap_size": 0, "stream_count": 0, "matched_response_streams": 0, "channels": 0})

        assert len(notes) == 1
        assert "没有捕获到完整数据包" in notes[0]
        assert "不要用 any" not in notes[0]
        assert "NET_RAW" in notes[0]

    @requires_node
    def test_wrong_mac_is_reported_before_stream_counts(self):
        """MAC 零命中时不该把用户引去查 TCP 流——过滤器本身就没匹配到。"""
        notes = _run_conclusions(
            {
                "pcap_size": 4096,
                "stream_count": 0,
                "matched_response_streams": 0,
                "channels": 0,
                "mac_requested": "48:57:02:25:bb:e3",
                "mac_seen_count": 0,
                "mac_not_seen": True,
            }
        )

        assert len(notes) == 1
        assert "48:57:02:25:bb:e3" in notes[0]
        assert "没有出现" in notes[0]

    @requires_node
    def test_no_tcp_stream_blames_the_filter_not_the_parser(self):
        notes = _run_conclusions(
            {"pcap_size": 2048, "stream_count": 0, "matched_response_streams": 0, "channels": 0}
        )

        assert len(notes) == 1
        assert "没有重组出任何 TCP 流" in notes[0]

    @requires_node
    def test_unmatched_streams_blame_the_stb_ip(self):
        notes = _run_conclusions(
            {"pcap_size": 2048, "stream_count": 70, "matched_response_streams": 0, "channels": 0}
        )

        assert len(notes) == 1
        assert "70 条 TCP 流" in notes[0]
        assert "机顶盒 IP" in notes[0]

    @requires_node
    def test_matched_streams_without_channels_blame_capture_window(self):
        notes = _run_conclusions(
            {"pcap_size": 2048, "stream_count": 35, "matched_response_streams": 35, "channels": 0}
        )

        assert len(notes) == 1
        assert "35 条响应流" in notes[0]
        assert "开机" in notes[0]

    @requires_node
    def test_success_reports_the_full_chain(self):
        notes = _run_conclusions(
            {"pcap_size": 5_242_880, "stream_count": 35, "matched_response_streams": 12, "channels": 156}
        )

        assert len(notes) == 1
        assert "解析完成" in notes[0]
        assert "未验证实际播放" in notes[0]
        assert "5.0 MB" in notes[0]
        assert "156" in notes[0]

    @requires_node
    def test_each_breakpoint_produces_a_distinct_conclusion(self):
        """五个断点必须给出五段不同的话，否则等于没诊断。"""
        cases = [
            {"pcap_size": 0, "stream_count": 0, "matched_response_streams": 0, "channels": 0},
            {"pcap_size": 1, "stream_count": 0, "matched_response_streams": 0, "channels": 0, "mac_not_seen": True, "mac_requested": "aa:bb:cc:dd:ee:ff"},
            {"pcap_size": 1, "stream_count": 0, "matched_response_streams": 0, "channels": 0},
            {"pcap_size": 1, "stream_count": 9, "matched_response_streams": 0, "channels": 0},
            {"pcap_size": 1, "stream_count": 9, "matched_response_streams": 9, "channels": 0},
            {"pcap_size": 1, "stream_count": 9, "matched_response_streams": 9, "channels": 9},
        ]
        rendered = {tuple(_run_conclusions(case)) for case in cases}

        assert len(rendered) == len(cases)


class TestDiagnosticsRowRendering:
    """行渲染要按字段存在与否取值，且对文本做转义。"""

    @requires_node
    def test_rows_follow_the_fields_the_backend_actually_sent(self):
        rows = _run_render_rows(
            {
                "pcap_size": 5_242_880,
                "mac_requested": "48:57:02:25:bb:e3",
                "mac_seen_count": 59812,
                "stream_count": 154,
                "matched_response_streams": 12,
                "channels": 156,
            }
        )
        html = "".join(rows)

        assert "抓包大小" in html and "5.0 MB" in html
        assert "48:57:02:25:bb:e3" in html
        assert "59,812" in html
        assert "154" in html
        assert "156" in html

    @requires_node
    def test_rows_skip_fields_that_are_absent(self):
        """只按 MAC 过滤的旧部署没有mac_* 字段，行不能因此多出空标签。"""
        html = "".join(
            _run_render_rows({"pcap_size": 1024, "stream_count": 3, "matched_response_streams": 1, "channels": 0})
        )

        assert "过滤 MAC" not in html
        assert "该 MAC 出现次数" not in html
        assert "TCP 流" in html

    @requires_node
    def test_rows_escape_untrusted_text(self):
        html = "".join(_run_render_rows({"mac_requested": '<img src=x onerror="alert(1)">', "pcap_size": 1}))

        assert "<img" not in html
        assert "&lt;img" in html

    @requires_node
    def test_empty_diagnostics_hides_the_panel(self):
        assert _run_render_hidden({}) is True
        assert _run_render_hidden({"diagnostics": {}}) is True


def _run_render_rows(diag: dict) -> list[str]:
    script = (
        f"{_extract_function('escapeHtml')}\n"
        f"{_extract_function('formatBytes')}\n"
        f"{_extract_function('stbDiagnosticsConclusions')}\n"
        f"{_extract_function('renderStbDiscoveryDiagnostics')}\n"
        "const tbody = {innerHTML: ''};"
        "const details = {hidden: false};"
        "const conclusion = {innerHTML: ''};"
        "global.$ = (id) => ({stbDiscoveryDiagnostics: details, stbDiscoveryDiagBody: tbody,"
        " stbDiscoveryDiagConclusion: conclusion}[id] || null);"
        f"renderStbDiscoveryDiagnostics({{diagnostics: {json.dumps(diag)}}});"
        "console.log(JSON.stringify(tbody.innerHTML.split('</tr>').filter(Boolean)));"
    )
    result = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _run_render_hidden(state: dict) -> bool:
    script = (
        f"{_extract_function('escapeHtml')}\n"
        f"{_extract_function('formatBytes')}\n"
        f"{_extract_function('stbDiagnosticsConclusions')}\n"
        f"{_extract_function('renderStbDiscoveryDiagnostics')}\n"
        "const details = {hidden: false};"
        "global.$ = (id) => ({stbDiscoveryDiagnostics: details,"
        " stbDiscoveryDiagBody: {innerHTML: ''}, stbDiscoveryDiagConclusion: {innerHTML: ''}}[id] || null);"
        f"renderStbDiscoveryDiagnostics({json.dumps(state)});"
        "console.log(JSON.stringify(details.hidden));"
    )
    result = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)
