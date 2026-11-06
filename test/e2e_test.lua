-- End-to-end paste into a scratch session, from a named pasteboard. Copy an image or file to
-- the board first, then: rex do test/e2e_test.lua board=<name> [host=<remote host>]
-- Without host the session is local.
local dir = debug.getinfo(1, "S").source:gsub("^@", ""):match("^(.*)/[^/]+$")
local actions, action, exec = {}, rex.action, rex.exec
rex.action = function(def) actions[def.name] = def.run end
dofile(dir .. "/../init.lua").setup(rex.args.options)
rex.action = action
local board = assert(rex.args.board)
rex.exec = setmetatable({start=exec.start}, {__call=function(_, argv, opts)
  opts = opts or {}
  opts.env = opts.env or {}
  opts.env.REX_PASTE_TEST_BOARD = board
  if rex.args.connections then opts.env.REX_PASTE_CONNECTIONS = tostring(rex.args.connections) end
  return exec(argv, opts)
end})
local function now()
  local r = exec{"/usr/bin/python3", "-c", "import time; print(time.time())"}
  assert(r.ok, r.stderr)
  return tonumber(r.stdout)
end
local host = rex.args.host
local remote = host and rex.server(host) or rex
local s = assert(remote.call("session.create", {label="rex-paste-clipboard-test", initial_windows={
  {layout={block={flavor="com.superlogical.terminal.shell", options={}}}},
}}))
local sid = s.session_id
remote.call("session.attach", {session_id=sid})
local view = assert(remote.call("session.view", {session_id=sid}))
local ctx = {server=host, session_id=sid, block_id=view.windows[1].focused_block_id}
local times = {}
local ok, err = pcall(function()
  for i=1,2 do
    local start = now()
    local result = actions.rex_paste(ctx)
    times[i] = {seconds=now()-start, result=result}
  end
  local screen = assert(remote.call("com.superlogical.terminal.format", {
    session_id=sid, block_id=ctx.block_id, args={format="text", unwrap=true},
  }))
  -- Local pastes show their shell-quoted path; remote ones land in the receiver's cache.
  local path = times[1].result.path
  local expected = path and "'" .. path:gsub("'", "'\\''") .. "'" or "rex-paste/v2/"
  assert(screen.content:find(expected, 1, true), "Pasted path missing: " .. expected)
end)
rex.exec = exec
remote.call("session.destroy", {session_id=sid})
assert(ok, err)
return {first=times[1], repeat_paste=times[2]}
