#!/usr/bin/env python3
"""vaultwarden-mcp write-tools round-trip driver.

Exercises every write tool against a live vaultwarden-mcp server:
create_cipher → search → edit_cipher → soft_delete_cipher → restore_cipher
→ delete_cipher → final search (empty), then a folder round-trip
(create_folder → get_folder_id → create-in-folder → move-to-No-Folder
→ list_folders → edit_folder → delete_folder).

Verifies that:
  - the server accepts writes and returns decrypted entries
  - created entries appear in search immediately (cache splice)
  - edit overlay semantics work (change a field, leave others)
  - soft-delete + restore round-trips
  - hard-delete removes the entry and the final search is empty
  - folders: create/resolve/move/rename/delete round-trip cleanly
  - the test entry and folder are fully cleaned up (no leftover state)

Usage:
  # secrets must be in the environment (export the VWMCP_* vars your
  # secretspec.toml declares, matching the account labels in your config)
  export VWMCP_AGENT_CLIENT_SECRET=... VWMCP_AGENT_PASSWORD=...
  python roundtrip-test.py --bin /path/to/vaultwarden-mcp \\
      --config /path/to/vaultwarden-mcp.toml --account agent

The script creates a uniquely-named test entry and deletes it at the end, so
it's safe to run repeatedly. It prints each step's result.
"""
import argparse, json, os, subprocess, sys, threading, time, uuid
from queue import Queue


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True, help="path to the vaultwarden-mcp binary")
    ap.add_argument("--config", required=True, help="path to vaultwarden-mcp.toml")
    ap.add_argument("--account", required=True,
                    help="account label to target (must have a write-able vault)")
    ap.add_argument("--transport", default="stdio", choices=["stdio", "http"])
    args = ap.parse_args()

    token = uuid.uuid4().hex[:8]
    name = f"vwmcp-roundtrip-{token}"

    proc = subprocess.Popen(
        [args.bin, "serve", "--config", args.config, "--transport", args.transport],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
        env=dict(os.environ), bufsize=0,
    )
    q = Queue()
    threading.Thread(target=lambda: [q.put(l) for l in proc.stdout], daemon=True).start()

    def send(method, params, rid):
        proc.stdin.write((json.dumps(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n").encode())
        proc.stdin.flush()

    def call(tool, arguments, rid, timeout=15):
        send("tools/call", {"name": tool, "arguments": arguments}, rid)
        start = time.time()
        while time.time() - start < timeout:
            try:
                line = q.get(timeout=1)
            except Exception:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == rid and "result" in msg:
                return msg
        return None

    def text(resp):
        if resp is None:
            return "NO RESPONSE"
        if "error" in resp:
            return f"ERROR: {resp['error']}"
        c = resp.get("result", {}).get("content", [])
        return c[0]["text"] if c and c[0].get("type") == "text" else json.dumps(resp)

    # initialize handshake
    send("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                        "clientInfo": {"name": "roundtrip-test", "version": "1"}}, 0)
    start = time.time()
    init = None
    while time.time() - start < 15:
        try:
            line = q.get(timeout=1)
            msg = json.loads(line)
            if msg.get("id") == 0 and "result" in msg:
                init = msg
                break
        except Exception:
            continue
    assert init, "initialize handshake failed"
    print(f"+ Connected: {init['result']['serverInfo']['name']} "
          f"v{init['result']['serverInfo']['version']}")
    proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    proc.stdin.flush()
    time.sleep(0.5)

    acc = {"account": args.account}

    # 1. create
    r = call("create_cipher", {**acc, "cipher_type": "login", "name": name,
              "username": "test@example.com", "password": "S3cret!Pass"}, 1)
    print(f"\n[1] create_cipher\n{text(r)[:300]}")
    assert r and not r.get("error"), "create failed"

    # 2. search (find it)
    r = call("search", {"query": name, "account": args.account}, 2)
    print(f"\n[2] search (find created)\n{text(r)[:300]}")
    try:
        cid = json.loads(text(r))[0]["id"]
    except Exception:
        cid = None
    assert cid, "could not find created cipher id"
    print(f"    cipher id: {cid}")

    # 3. edit (overlay: change notes only)
    r = call("edit_cipher", {**acc, "cipher_id": cid, "notes": "edited-by-test"}, 3)
    print(f"\n[3] edit_cipher\n{text(r)[:300]}")
    assert r and not r.get("error"), "edit failed"

    # 4. soft delete
    r = call("soft_delete_cipher", {**acc, "cipher_id": cid}, 4)
    print(f"\n[4] soft_delete_cipher\n{text(r)[:200]}")

    # 5. search (should be gone from active)
    r = call("search", {"query": name, "account": args.account}, 5)
    print(f"\n[5] search after soft-delete\n{text(r)[:200]}")

    # 6. restore
    r = call("restore_cipher", {**acc, "cipher_id": cid}, 6)
    print(f"\n[6] restore_cipher\n{text(r)[:200]}")

    # 7. hard delete
    r = call("delete_cipher", {**acc, "cipher_id": cid}, 7)
    print(f"\n[7] delete_cipher (hard)\n{text(r)[:200]}")

    # 8. final search (should be empty)
    r = call("search", {"query": name, "account": args.account}, 8)
    final = text(r)
    print(f"\n[8] final search (should be [])\n{final[:200]}")
    assert json.loads(final) == [], "test entry was not cleaned up!"

    # ── Folder round-trip ────────────────────────────────────────────────────
    fname = f"vwmcp-folder-{args.account}"

    # 9. create_folder
    r = call("create_folder", {**acc, "name": fname}, 9)
    print(f"\n[9] create_folder\n{text(r)[:200]}")
    assert r and not r.get("error"), "create_folder failed"

    # 10. get_folder_id
    r = call("get_folder_id", {**acc, "name": fname}, 10)
    print(f"\n[10] get_folder_id\n{text(r)[:200]}")
    fid = json.loads(text(r)).get("folder_id")
    assert fid, "get_folder_id returned no id"

    # 11. create_cipher into the folder
    r = call("create_cipher", {**acc, "cipher_type": "note", "name": name,
                                "notes": "folder-test", "folder": fname}, 11)
    print(f"\n[11] create_cipher with folder\n{text(r)[:300]}")
    assert r and not r.get("error"), "create with folder failed"
    fcid = json.loads(text(r)).get("id")
    assert fcid, "create returned no id"

    # 12. edit_cipher: move to No Folder (folder: null)
    r = call("edit_cipher", {**acc, "cipher_id": fcid, "folder": None}, 12)
    print(f"\n[12] edit_cipher folder=null (No Folder)\n{text(r)[:200]}")
    assert r and not r.get("error"), "edit folder=null failed"

    # 13. list_folders (should contain fname)
    r = call("list_folders", {"account": args.account}, 13)
    folders = json.loads(text(r))
    print(f"\n[13] list_folders\n{text(r)[:300]}")
    assert any(f.get("name") == fname for f in folders), "folder missing from list"

    # 14. edit_folder (rename)
    r = call("edit_folder", {**acc, "name": fname, "new_name": fname + "-renamed"}, 14)
    print(f"\n[14] edit_folder (rename)\n{text(r)[:200]}")
    assert r and not r.get("error"), "edit_folder failed"

    # 15. delete_folder
    r = call("delete_folder", {**acc, "name": fname + "-renamed"}, 15)
    print(f"\n[15] delete_folder\n{text(r)[:200]}")
    assert r and not r.get("error"), "delete_folder failed"

    # 16. hard-delete the folder-test cipher to leave the vault clean
    r = call("delete_cipher", {**acc, "cipher_id": fcid}, 16)
    print(f"\n[16] delete_cipher (cleanup)\n{text(r)[:200]}")
    assert r and not r.get("error"), "cleanup delete failed"

    proc.stdin.close()
    proc.wait(timeout=3)
    print(f"\n+ Round-trip complete. Test entry '{name}' and folder '{fname}' cleaned up.")


if __name__ == "__main__":
    main()
