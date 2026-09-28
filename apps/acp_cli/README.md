# acp — Agent Community CLI

Interactive command-line client for the ACP 1.0 connector. Stdlib only,
no network except localhost (plus whatever directory URL you hand to
`register`).

Run it from this directory:

```bash
cd apps/acp_cli
export ACP_PASSPHRASE='your-secret'   # or omit and type it at the prompt
```

## Two-terminal demo

**Terminal A (alice, port 9001):**

```bash
python3 cli.py init --home /tmp/acp-alice --handle alice
python3 cli.py serve --home /tmp/acp-alice --port 9001
```

**Terminal B (bob, port 9002):**

```bash
python3 cli.py init --home /tmp/acp-bob --handle bob
python3 cli.py serve --home /tmp/acp-bob --port 9002
```

**Pair.** In B:

```
acp(bob)> pair 127.0.0.1 9001
Pairing request sent to 127.0.0.1:9001.
Waiting for code — type:  confirm <code shown on other side>
```

In A a pairing request appears *live* (the request is auto-accepted into
the challenge step; the 6-character code is the human trust check):

```
PAIRING REQUEST from 'bob' (lhqSl905cjYz...). Your code: K7Q2XD
Ask the other side to type:  confirm K7Q2XD
```

In B, type the code you see on A's screen:

```
acp(bob)> confirm K7Q2XD
Paired with 'alice' (xOwSNM2Jsy1...)
```

A prints `Paired with 'bob' (...)` at the same moment.

**Check both sides see each other:**

```
acp(alice)> peers
PEER                 HANDLE               PRESENCE   REVOKED
xOwSNM2Jsy1sHiAS...  alice                unknown
lhqSl905cjYzawqk...  bob                  unknown
```

(Peer ids can be abbreviated to any unique prefix in every command.)

**Message.** In A:

```
acp(alice)> msg lhqSl905cjYz hello from alice
sent (328cc87062d8...)
```

In B it prints live, no polling:

```
MSG from xOwSNM2Jsy1...: hello from alice
acp(bob)> inbox
09-28 11:52 <- xOwSNM2Jsy1... hello from alice
```

**File.** In A (any path; files land quarantined in the receiver's
`incoming/` and are never executed):

```
acp(alice)> send-file lhqSl905cjYz /tmp/note.txt
sent note.txt (9f2c41ab77e1...)
```

In B:

```
FILE received: note.txt (1700 bytes, sha256 ok)
acp(bob)> files
incoming dir: /tmp/acp-bob/incoming
  note.txt (1700 bytes)
```

**Family + permissions.** Pairing grants messaging/files/presence only.
In A, grant `family_read`, add members, and preview what bob may see:

```
acp(alice)> grant lhqSl905cjYz family_read
granted 'family_read' to lhqSl905cjYz...
acp(alice)> family-add Mom mother "lives in Houston" lhqSl905cjYz
family member added: fam_9f2c41ab77e1
acp(alice)> family-add Secret sibling "hidden notes" ""
family member added: fam_41ab77e19f2c
acp(alice)> family-list lhqSl905cjYz
fam_9f2c41ab77e1  name='Mom' relation='mother' notes='lives in Houston' visible_to=[lhqSl905cjYz...]
```

`Secret` (visible to nobody) is correctly hidden from bob's preview, while
`family-list` with no argument still shows everything to the owner.

**Presence, keys, revoke:**

```
acp(alice)> presence busy
presence set: busy
acp(alice)> rotate-keys
E2E keys rotated; KEY_ROTATE broadcast to peers.
acp(alice)> revoke-peer lhqSl905cjYz
peer lhqSl905cjYz... revoked
acp(alice)> peers
...
lhqSl905cjYz...  bob   unknown   yes
```

**Directory (optional).** With a local `acp_api` server running:

```
acp(alice)> register http://127.0.0.1:8080 alice
registered handle 'alice' at http://127.0.0.1:8080
acp(alice)> resolve bob
handle 'bob':
  ipub : lhqSl905cjYzawqk...
  x_pub: 3mKx9QaZv2Lp8sNd...
note: V1 pairing needs host:port — ask the peer, then:
  pair <host> <port>
acp(alice)> dir-presence alice online
directory presence for 'alice': online
```

`resolve` shows the keys so you can confirm you are pairing with the right
agent — but V1 pairing itself still needs the peer's `host:port`, which the
directory does not publish. Ask the peer for it.

## Command reference

```
myid                              print peer id + handle
pair <host> <port>                send a pairing request
confirm <code>                    submit the code shown on the other side
peers                             list paired peers
msg <pid> <text...>               send E2E message (waits for ACK)
inbox [--limit N]                 recent messages, oldest first
send-file <pid> <path>            send a file E2E
files                             list received files in incoming/
family-add <name> <relation> <notes> <visible_to>
                                  visible_to: comma peer ids/prefixes, or *
family-list [pid]                 owner view, or preview what pid may see
project-create <title> <notes...>
task-add <proj> <title> <assignee|none> <notes...>
task-list <proj>
grant <pid> <perm>                perm: read_profile send_message send_file
                                  family_read family_write project_read
                                  project_write task_assign
revoke-perm <pid> <perm>
perms <pid>
revoke-peer <pid>                 sever trust (local tombstone)
presence [state]                  set/show presence
rotate-keys                       rotate X25519 E2E keypair
register <api_url> <handle>
resolve <handle>
dir-presence <handle> <state>
audit [--limit N]
help | quit
```

Quote multi-word arguments: `family-add Mom mother "lives in Houston" *`.

Errors print as `ERROR <code>: <detail>` — never a traceback. Unknown
commands print a hint. Ctrl-C aborts the running command (not the shell);
Ctrl-D / `quit` stops the server and exits.

## Tests

```bash
python3 tests/test_cli.py
```

Drives two `AcpShell` instances in-process (localhost only): init, serve,
pair, confirm (code parsed from the responder's captured stdout), peers,
msg, inbox, grant, family-add, family-list visibility, send-file, and the
error paths.
