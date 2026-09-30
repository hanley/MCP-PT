# infrastructure/execution/ 

Topology deployment strategies. They implement different ways to bring a `TopologyPlan` to Packet Tracer or to disk. 

## Architecture

```
ExecutorBase (ABC) 
├── ManualExecutor → Export files to disk 
└── DeployExecutor → Export + copy to clipboard + instructions 

Channels to Packet Tracer (server chooses ONE per command): 
├── PTCommandBridge (live_bridge.py) → local HTTP Bridge 
(port 54321) 
│ when the extension window is open 
└── FileBridge (file_bridge.py) → Disk Archive Mailbox 
When the window is closed 
                                         when the window is closed

bridge_token.py → auto-generated local token that authenticates the HTTP bridge
```

**Channel routing**: The server decides by command (see `_pick_channel` in 
`adapters/mcp/tool_registry.py`) if the command travels over HTTP or over the file mailbox. 
Never use both at once. Sending the plan when deploying is done in batches.

## Archives 

### 'executor_base.py' — Abstract Base Class

```python
class ExecutorBase(ABC):
    def execute(plan, project_name) → dict    # Abstract
    def is_available() → bool                  # Abstract
```

A contract that all executors must fulfill.

---

### `manual_executor.py` — Export to disk

Exports all plan artifacts as files to the file system.

```python
class ManualExecutor(ExecutorBase):
    def execute(plan, project_name) → dict
    def is_available() → True  # Always available
```

**Files generated:** 
| Archive | Contents | 
|---------|-----------| 
| `topology.js` | Basic PTBuilder Script (addDevice + addLink) | 
| `full_build.js` | Full Script with Settings | 
| `{Device}_config.txt` | Config CLI per device (R1, SW1, etc.) | 
| `plan.json` | Complete Serialized Plan | 
| `metadata.json` | Project metadata (name, date, counts) |

---

### 'deploy_executor.py' — Clipboard deployment 

Extend the export to disk by adding copy to the clipboard and generating step-by-step instructions.


```python
class DeployExecutor(ExecutorBase):
    def __init__(output_dir="projects")
    def execute(plan, project_name) → dict
```

**Flow:** 
1. Generate scripts and configs (same as ManualExecutor) 
2. Copy `topology.js` to the clipboard (Windows only via `clip.exe`) 
3. Save all files to disk 
4. Generate step-by-step instructions for the user 

**Note**: The clipboard feature only works on Windows. On macOS/Linux, files are exported but clipboard is skipped.

---

### 'live_bridge.py' — HTTP Bridge for Packet Tracer (~300 lines) 

Local HTTP server that allows two-way communication between Python and Packet Tracer in real time.

```python
class PTCommandBridge:
    def __init__(port=54321, token=None)
    def start() → None
    def put_result(rid, body) → None          # the POST /result handler calls it
    def take_result(rid, wait) → str | None   # awaits the result of that operation
    def drain_commands() → list[str]
    @property
    def is_connected → bool

# Module Functions
def next_rid() → str                          # Operation ID, PID + Counter
def report_result_js(port, token, rid) → str  # the rid travels within the JS
```

The MCP adapter talks to the bridge **over HTTP**, not by calling methods from the 
Instance: The bridge may have been started by another process.

**Endpoints HTTP:**
| Method | Route | Description | 
|--------|------|-------------| 
| `GET` | `/next` | PTBuilder polling — returns the batch of JS commands from the queue | 
| `GET` | `/ping` | Basic health check (no token, doesn't leak the secret) | 
| `GET` | `/status` | Detailed Bridge Status | 
| `GET` | `/result` | Collects the result of `?rid=...`, waiting until `?wait=...` seconds | 
| `POST` | `/result` | PTBuilder sends the result of `?rid=...` | 
| `POST` | `/queue` | Queue a JS command externally | 

**Correlation by `rid`:** each trade generates its own (`next_rid()`), travels inside the injected JS and PT returns it when posting. Before, the results were a global FIFO queue and the handler waited for a fixed 9 s, so a trade was considered a failure *and* its late result was orphaned so that it could be the next one will take you. The extension never constructs the URL of `/result` — only executes the JS that comes to him—, that's why the change didn't touch the `.pts`.

**Design:**
```
Python (PTCommandBridge)         PT Builder (QWebEngine)
       ↓                              ↓
  POST /queue ──→ cola ─────→ GET /next (polling 500ms)
                                       ↓
                               $se('runCode', cmd)
                                       ↓
                               POST /result ──→ callback
```

**Authentication:** The HTTP bridge requires a self-generated local token (see `bridge_token.py`). No bootstrap pasted by hand or HTTP pairing — the extension reads the token from disk.

---

### 'file_bridge.py' — Archive Mailbox (Offline Channel) 

Alternative channel to HTTP for when the extension window is closed. Instead of an HTTP server, uses a file mailbox under `%LOCALAPPDATA%\packet-tracer-mcp\bridge\`: the server writes a `req_*.js`, the PT Script Engine reads it, executes it, and leaves the Answer in a `res_*.txt`.

### `file_bridge.py` — Buzón de archivos (canal offline)

```python
class FileBridge:
    def send(js_code) → bool
    def send_and_wait(js_code, timeout) → str | None
```

Coexists with the HTTP bridge; the server chooses one channel per command (`_pick_channel`), never both.

---

### 'bridge_token.py' — Local token of the HTTP bridge 

Generates and persists a local token (under `%LOCALAPPDATA%`) that authenticates requests to the HTTP bridge. It is self-generating; it does not require a bootstrap or manual pairing. Both the server and extension read it from disk.