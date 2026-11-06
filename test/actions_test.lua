-- Action tests with mocked helpers and servers: rex do test/actions_test.lua
-- Covers text, local and remote images and files, the remote image cache, failure cleanup,
-- receiver version checks, the receiver, and setup{} validation.
local dir = debug.getinfo(1, "S").source:gsub("^@", ""):match("^(.*)/[^/]+$")
local saved = {action=rex.action, exec=rex.exec, call=rex.call, server=rex.server}
local actions = {}
rex.action = function(def) actions[def.name] = def.run end
local plugin = dofile(dir .. "/../init.lua")
plugin.setup()
-- State lives in a table: Rex Lua closures keep stale upvalues after a caught error.
local s = {mode="text", hit=false, fail=false, events={}, pool=0, notices={}, progress={}, waiters=0, attached={}}
local text = "  café résumé\nsecond line\t\n\n"
local hash, token = string.rep("a", 64), string.rep("b", 32)
local function response(value) return {ok=true, stdout=assert(rex.json.encode(value))} end
local rex_cli = "/Apps/Rex Server.app/Contents/MacOS/rex"
local exec = function(argv, opts)
  if argv[1] == "/bin/ps" then
    assert(argv[2] == "-o" and argv[3] == "comm=" and argv[4] == "-p" and argv[5] == "42")
    s.ps = (s.ps or 0) + 1
    return {ok=true, stdout=rex_cli .. "\n"}
  end
  assert(argv[1]:match("/bin/rex%-paste$") and opts.text == false)
  s.env = opts.env
  local op = argv[2]
  if op == "clipboard" then
    if s.mode == "text" then return response{kind="text", text=text} end
    if s.mode == "file" then return response{kind="file", path=s.path or "/tmp/a'b.pdf", transfer_id=token} end
    return response{kind="image", path="/tmp/a'b.png", sha256=hash, transfer_id=token}
  elseif op == "prepare" then
    assert(argv[3] == "/tmp/a'b.png")
    return response{path="/tmp/a'b.png", sha256=hash}
  elseif op == "send" then
    local kind = s.mode == "file" and "file" or "image"
    assert(argv[3] == kind and argv[4] == "/tmp/a'b." .. (kind == "file" and "pdf" or "png"))
    assert(argv[5] == "test-host" and argv[6] == "session:test" and argv[7] == "block:test" and argv[8] == token)
    s.events[#s.events + 1] = "send-" .. kind
    if s.fail then return {ok=false, stderr="simulated failure"} end
    return response{ok=true, sha256=hash}
  elseif op == "push" or op == "lookup" or op == "discard" then
    s.events[#s.events + 1] = op
    return response{path=s.hit and "/home/u/.cache/rex-paste/v2/x.png" or nil, progress=s.slow and 51 or nil}
  end
  error("Unexpected helper command " .. tostring(op))
end
rex.exec = setmetatable({start=function(argv)
  if argv[1] == rex_cli then
    -- An update notice's waiter: rex [-S <host>] do -s <session> notice.lua --args <json>
    assert(argv[#argv - 2]:match("/notice%.lua$") and argv[#argv - 1] == "--args")
    local args = assert(rex.json.decode(argv[#argv]))
    assert(args.block == "block:float" and args.mute_text)
    s.waiters = s.waiters + 1
    return
  end
  assert(argv[2] == "serve" and argv[3] == rex_cli and argv[4] == "test-host" and argv[5] == "42")
  s.pool = s.pool + 1
end}, {__call=function(_, ...) return exec(...) end})
-- Session calls on connection `who`, which must be attached for them, as in Rex. Floats:
-- notices take the keyboard and show their text; progress floats run the binary.
local function float(who, method, args)
  if method == "session.attach" or method == "session.detach" then
    s.attached[who] = method == "session.attach" or nil
    return {}
  end
  if not s.attached[who] then return nil, "stream is not attached to session" end
  if method == "session.view" then
    return {windows={{window_id="window:test", layers={{kind="tiled",
      layout={rect={0, 0, 1, 1}, split={before={rect={0, 0, 0.5, 1}, block_id="block:other"},
        after={rect={0.5, 0, 0.5, 1}, block_id="block:test"}}}}}}}}
  elseif method == "com.superlogical.terminal.size" then
    return {columns=100, rows=40}
  end
  assert(method == "session.new_layer" and args.window_id == "window:test")
  local b = args.bounds
  -- Sized for the window the terminal is in (40 rows), not the fallback (50).
  assert(math.abs(b[4] * 40 - (args.layout.block.options.size.rows + 4.5)) < 1e-9, "terminal not found")
  assert(b[1] >= 0 and b[2] >= 0 and b[1] + b[3] <= 1 and b[2] + b[4] <= 1)
  local command = args.layout.block.options.command
  if args.focus then
    s.notices[#s.notices + 1] = command[5]
  else
    assert(command[1]:match("/bin/rex%-paste$") and command[2] == "progress" and command[3] == token)
    s.progress[#s.progress + 1] = command[4]
  end
  return {layer_id="layer:float", block_ids={"block:float"}}
end
-- Pastes on connection `who`, which must be attached, as in Rex.
local function paste(who, method, args)
  if method == "server.status" then return {pid=42} end
  if method ~= "block.event" then return float("local", method, args) end
  assert(s.attached[who], who .. " pasted without attaching")
  assert(args.session_id == "session:test" and args.block_id == "block:test")
  assert(args.event.type == "paste")
  local expected = {text=text, image="'/tmp/a'\\''b.png' ", file="'/tmp/a'\\''b.pdf' ",
    receive="'/home/u/.cache/rex-paste/v2/x.png' "}
  assert(args.event.payload.text == expected[s.mode], args.event.payload.text)
  s.events[#s.events + 1] = "paste"
  return {}
end
rex.call = function(method, args) return paste("local", method, args) end
rex.server = function(host)
  assert(host == "test-host")
  return {call=function(method, args)
    if method == "block.event" then return paste("remote", method, args) end
    if method ~= "client.action" then return float("remote", method, args) end
    assert(args.action == "rex_paste_receive")
    s.events[#s.events + 1] = args.args.op
    if args.args.op == "version" then
      if s.receiver == "missing" then
        return nil, 'stream response "control-1" failed: the configuration file defines no action '
          .. '"rex_paste_receive" (status=404 code=not_found)'
      end
      return {result={version=s.receiver or "dev"}}
    end
    if args.args.op == "lookup" then
      assert(args.args.sha256 == hash and args.args.session_id == "session:test" and args.args.block_id == "block:test")
      return {result=s.hit and {path="/remote/image.webp"} or {}}
    end
    assert(args.args.op == "discard" and args.args.token == token)
    return {result={}}
  end}
end
local function events() local e = table.concat(s.events, ","); s.events = {}; return e end
local local_ctx = {session_id="session:test", block_id="block:test"}
local remote_ctx = {server="test-host", session_id="session:test", block_id="block:test"}

-- Text keeps UTF-8 and whitespace; empty text pastes nothing.
actions.rex_paste(local_ctx)
actions.rex_paste(remote_ctx)
text = ""
actions.rex_paste(local_ctx)
assert(events() == "paste,paste")
assert(not s.attached["local"] and not s.attached["remote"], "a paste left its connection attached")

-- Images: local pastes the prepared path; remote checks the receiver and sends once, then a
-- cache hit only looks up. A failed transfer checks the receiver again.
s.mode = "image"
actions.rex_paste(local_ctx)
actions.rex_paste(remote_ctx)
s.hit = true
actions.rex_paste(remote_ctx)
s.hit = false -- the remote cache was deleted: send again
actions.rex_paste(remote_ctx)
s.fail = true
assert(not pcall(actions.rex_paste, remote_ctx))
assert(events() == "paste,version,send-image,lookup,lookup,send-image,lookup,send-image,discard,version")
assert(s.pool == 4)
assert(s.ps == 1, "the rex CLI is found once") -- from the server's pid, not a fixed path

-- Regular files: local pastes the original path; remote always sends.
s.mode, s.fail = "file", false
actions.rex_paste(local_ctx)
actions.rex_paste(remote_ctx)
s.fail = true
assert(not pcall(actions.rex_paste, remote_ctx))
assert(events() == "paste,send-file,send-file,discard,version")
-- A file name with control characters is never pasted: they would act as keystrokes.
s.path = "/tmp/x\27[201~\21rm -rf ~\r.png"
local ok, err = pcall(actions.rex_paste, local_ctx)
assert(not ok and err:find("control characters"), err)
assert(events() == "")
s.path = nil

-- A receiver of another version, or none, fails every paste with a notice of what to install.
s.receiver = "v0.0.1"
ok, err = pcall(actions.rex_paste, remote_ctx) -- s.fail: the transfer fails, the check explains it
assert(not ok and err:find("test-host has rex-paste v0.0.1, this Mac has dev.", 1, true), err)
assert(err:find("Install the same checkout on test-host.", 1, true), err)
s.fail = false
assert(not pcall(actions.rex_paste, remote_ctx))
s.receiver = "missing"
ok, err = pcall(actions.rex_paste, remote_ctx)
assert(not ok and err:find("test-host does not have rex-paste set up", 1, true), err)
assert(#s.notices == 3 and s.notices[3]:find(err, 1, true) and s.notices[3]:find("Press any key", 1, true))
assert(not s.attached.remote, "a notice left the connection attached")
s.receiver = nil
actions.rex_paste(remote_ctx)
assert(events() == "send-file,discard,version,version,version,version,send-file")

-- Receiver: a completed transfer pastes its path; incomplete chunks and discards do not.
s.mode, s.hit = "receive", true
local push = {op="push", token=token, session_id="session:test", block_id="block:test"}
assert(actions.rex_paste_receive(nil, push).path)
s.hit = false
assert(actions.rex_paste_receive(nil, push).path == nil)
actions.rex_paste_receive(nil, {op="discard", token=token})
assert(not pcall(actions.rex_paste_receive, nil, {op="other"}))
assert(actions.rex_paste_receive(nil, {op="version"}).version == "dev")
assert(events() == "push,paste,push,discard")
assert(not s.attached["local"], "the receiver left its connection attached")

-- A push the binary marks as slow opens a progress float, without the keyboard.
local chunk = {op="push", token=token, name="big.bin", session_id="session:test", block_id="block:test"}
actions.rex_paste_receive(nil, chunk)
assert(#s.progress == 0)
s.slow = true
actions.rex_paste_receive(nil, chunk)
assert(#s.progress == 1 and s.progress[1] == "big.bin")
assert(not s.attached["local"], "the progress float left the connection attached")
s.slow = nil
events()

-- setup{} options are validated, then reach every helper call as REX_PASTE_* variables.
assert(s.env.REX_PASTE_MAX_SIZE == "16777216" and s.env.REX_PASTE_CONNECTIONS == "12" and s.env.REX_PASTE_RESIZE == "1")
for _, bad in ipairs{{connections=0}, {resize="yes"}, {max_dimension=0}, {max_size=1.5}} do
  assert(not pcall(plugin.setup, bad))
end
plugin.setup{max_dimension=1000, resize=false, compress=false, connections=40.0}
s.mode = "text"
actions.rex_paste(local_ctx)
assert(s.env.REX_PASTE_MAX_DIMENSION == "1000" and s.env.REX_PASTE_RESIZE == "0"
  and s.env.REX_PASTE_COMPRESS == "0" and s.env.REX_PASTE_CONNECTIONS == "40")

rex.action, rex.exec, rex.call, rex.server = saved.action, saved.exec, saved.call, saved.server
return {passed=true}
