-- rex-paste: paste clipboard images and files into local and remote Rex sessions.
-- The same plugin runs on the Mac (sender) and on every Rex server host (receiver).
local M = {}

local dir = debug.getinfo(1, "S").source:gsub("^@", ""):match("^(.*)/[^/]+$")
local binary = dir .. "/bin/rex-paste"
local receive_action = "rex_paste_receive"
local releases = "https://github.com/jeongjinku/rex-paste/releases"

local function read_line(path)
  local f = io.open(path)
  if not f then return nil end
  local line = f:read("*l")
  f:close()
  return line
end

-- Release installs carry a VERSION file; a source checkout is "dev".
local version = read_line(dir .. "/VERSION") or "dev"

-- setup{} options. The binary reads them as REX_PASTE_* environment variables.
local defaults = {
  max_size = 16 * 1024 * 1024, -- bytes; one limit for prepared images and regular files
  resize = true,               -- downscale images to fit max_dimension
  max_dimension = 2000,        -- longest side in pixels
  compress = true,             -- lossless WebP; false keeps the original format
  connections = 12,            -- parallel Rex connections per remote host
}

local function integer(min, max)
  return function(v) return type(v) == "number" and v % 1 == 0 and v >= min and v <= max end
end
local function boolean(v) return type(v) == "boolean" end
local checks = {
  max_size = integer(1, 0xffffffff),
  resize = boolean,
  max_dimension = integer(1, 65535),
  compress = boolean,
  connections = integer(1, 65535),
}

local options, env = {}, {}

local function configure(opts)
  local o, e = {}, {}
  for k, v in pairs(defaults) do o[k] = v end
  for k, v in pairs(opts or {}) do
    if not checks[k] then
      rex.log("warn", "rex-paste: ignoring unknown option " .. tostring(k))
    elseif not checks[k](v) then
      error("rex-paste: invalid value for " .. k .. ": " .. tostring(v), 0)
    else
      o[k] = v
    end
  end
  for k, v in pairs(o) do
    e["REX_PASTE_" .. k:upper()] = type(v) == "boolean" and (v and "1" or "0") or tostring(v)
  end
  options, env = o, e
end

-- Runs the binary and returns its JSON output.
local function helper(stdin, ...)
  -- 150s base plus 1s per MiB of the size limit.
  local timeout = 150 + math.floor(options.max_size / 1048576)
  local r, err = rex.exec({binary, ...}, {stdin=stdin, text=false, env=env, timeout=timeout})
  if r and (r.timed_out or r.signal) then
    error({message="rex-paste: transfer interrupted", interrupted=true}, 0)
  end
  if not r or not r.ok then
    -- The binary's own messages already start with "rex-paste:".
    error(r and r.stderr ~= "" and (r.stderr:gsub("%s+$", "")) or "rex-paste: " .. tostring(err), 0)
  end
  return assert(rex.json.decode(r.stdout))
end

-- Every pasted path goes through here. Control characters are refused: in a file name they
-- would reach the terminal as keystrokes, such as Enter or the end of a bracketed paste.
local function quoted(path)
  if path:find("%c") then error("rex-paste: the file name has control characters", 0) end
  return "'" .. path:gsub("'", "'\\''") .. "' "
end

-- Calls fn(view) with server's connection attached to session_id, which most session calls,
-- block.event among them, need. A connection this attaches is detached again: an attached connection receives every
-- event of the session, and a pool connection that never reads them stalls.
local function in_session(server, session_id, fn)
  local view = server.call("session.view", {session_id=session_id}) -- nil unless attached
  if not view then
    local _, err = server.call("session.attach", {session_id=session_id})
    if err then error(tostring(err), 0) end
  end
  local ok, result = pcall(fn, view or server.call("session.view", {session_id=session_id}))
  if not view then server.call("session.detach", {session_id=session_id}) end
  if not ok then error(result, 0) end
  return result
end

-- Pastes text into target's terminal through server.
local function paste(server, target, text)
  in_session(server, target.session_id, function()
    local _, err = server.call("block.event", {
      session_id=target.session_id, block_id=target.block_id,
      event={type="paste", payload={text=text}},
    })
    if err then error(tostring(err), 0) end
  end)
end

-- Opens the smallest float that fits lines over a terminal, running command, on server (the
-- one holding the session) and returns the float's block. The window's size in cells is the
-- terminal's size divided by its share of the window.
local function open_float(server, session_id, block_id, lines, command, focus)
  return in_session(server, session_id, function(view)
    local function find(node)
      if not node then return nil end
      if node.block_id == block_id then return node.rect end
      return node.split and (find(node.split.before) or find(node.split.after))
    end
    local rect, window_id
    for _, window in ipairs(view and view.windows or {}) do
      for _, layer in ipairs(window.layers or {}) do
        local r = layer.kind == "tiled" and find(layer.layout)
        if r then rect, window_id = r, window.window_id end
      end
    end
    local size = server.call("com.superlogical.terminal.size", {session_id=session_id, block_id=block_id})
    local columns, rows = 200, 50 -- a guess when the terminal is not in the window's tiled layout
    if rect and size then columns, rows = size.columns / rect[3], size.rows / rect[4] end
    local width = 0
    for _, line in ipairs(lines) do width = math.max(width, #line) end
    -- Room for the float's frame, as measured in the Mac app: four rows and two columns, plus
    -- half a cell so rounding never wraps the text.
    local w, h = math.min(1, (width + 2.5) / columns), math.min(1, (#lines + 4.5) / rows)
    local layer, err = server.call("session.new_layer", {
      session_id=session_id, window_id=window_id, bounds={(1 - w) / 2, (1 - h) / 2, w, h}, focus=focus,
      layout={block={flavor="com.superlogical.terminal.shell", label="rex-paste", options={
        shell="none", login=false, size={columns=width, rows=#lines}, exit={quick_exit_threshold_ms=0},
        command=command,
      }}},
    })
    if err then error(tostring(err), 0) end
    return layer.block_ids[1]
  end)
end

-- The binary says when a transfer is still arriving after a second, and how wide its progress
-- line is; the transfer then gets a float showing its progress. The receiver opens it because
-- during a transfer only it has a free connection to this server.
local function show_progress(args, width)
  open_float(rex, args.session_id, args.block_id, {string.rep(" ", width)},
    {binary, "progress", args.token, args.name or "image"}, false)
end

-- Receiver: stores verified chunks and pastes the path once the transfer is complete.
local function receive(_, args)
  if args.op == "version" then return {version=version} end
  if args.op == "discard" then return helper(nil, "discard", args.token) end
  local result
  if args.op == "lookup" then
    result = helper(nil, "lookup", args.sha256)
  elseif args.op == "push" then
    result = helper(assert(rex.json.encode(args)), "push")
    if result.progress then pcall(show_progress, args, result.progress) end
  else
    error("rex-paste: invalid request", 0)
  end
  if result.path then paste(rex, args, quoted(result.path)) end
  return result
end

local function call_receiver(remote, args)
  local r, err = remote.call("client.action", {action=receive_action, args=args})
  if err then error(tostring(err), 0) end
  return r.result
end

-- The Rex server's pid, and its executable, which is also the rex CLI that pools and notices
-- run. The server has no setting or variable for its path, so ps reads it from the pid.
local rex_cli
local function rex_server()
  local status = assert(rex.call("server.status"), "rex-paste: Rex server status unavailable")
  if not rex_cli then
    local r = rex.exec({"/bin/ps", "-o", "comm=", "-p", tostring(status.pid)}, {timeout=5})
    rex_cli = assert(r and r.ok and r.stdout:match("^%s*(/.-)%s*$"), "rex-paste: cannot find the rex CLI")
  end
  return status.pid, rex_cli
end

-- Starts the connection pool for host; a pool that is already running with these settings stays.
local function start_pool(host)
  local pid, cli = rex_server()
  rex.exec.start({binary, "serve", cli, host, tostring(pid)}, {detach=true, stdout=false, stderr=false, env=env})
end

local cache = (os.getenv("HOME") or "") .. "/.cache/rex-paste"
local update_file = cache .. "/update-check" -- when the update check last ran, as os.time()
local latest_file = cache .. "/update-latest" -- the latest release the last check found
local mute_file = cache .. "/update-muted" -- the release whose notice the user turned off

-- Shows text in a float over the pasted-into terminal until a key is pressed. With mute,
-- notice.lua waits for the float to close and records n, which turns off the notice for that
-- release; it runs detached because Rex takes no input while a key-bound action runs.
local function notice(host, ctx, text, mute)
  local lines = {}
  for line in (text .. "\n"):gmatch("(.-)\n") do lines[#lines + 1] = line end
  lines[#lines + 1] = ""
  lines[#lines + 1] = mute and "Press n to stop this notice for " .. mute .. ", any other key to close."
    or "Press any key to close."
  local block = open_float(host and rex.server(host) or rex, ctx.session_id, ctx.block_id, lines, {
    "/bin/sh", "-c", 'printf "%s" "$1"; stty -icanon -echo; [ "$(dd bs=1 count=1 2>/dev/null)" != n ]',
    "rex-paste", table.concat(lines, "\n"),
  }, true)
  if not mute then return end
  local _, cli = rex_server()
  local argv = {cli}
  if host then argv[2], argv[3] = "-S", host end
  local args = assert(rex.json.encode({block=block, mute_file=mute_file, mute_text=mute}))
  for _, a in ipairs{"do", "-s", ctx.session_id, dir .. "/notice.lua", "--args", args} do argv[#argv + 1] = a end
  rex.exec.start(argv, {detach=true, stdout=false, stderr=false})
end

-- Returns why host cannot receive from this sender, or nil when it runs the same version.
local function receiver_problem(host, remote)
  local r, err = remote.call("client.action", {action=receive_action, args={op="version"}})
  local missing = err and tostring(err):find('defines no action "' .. receive_action .. '"', 1, true)
  if err and not missing then error(tostring(err), 0) end
  local theirs = not missing and r.result and r.result.version
  if theirs == version then return nil end
  local lines = {("rex-paste: %s %s, this Mac has %s. Pasting there fails until they match."):format(host,
    theirs and "has rex-paste " .. tostring(theirs) or "does not have rex-paste set up", version)}
  if version == "dev" then
    lines[2] = "Install the same checkout on " .. host .. "."
  else
    lines[2] = "On " .. host .. ", run:"
    lines[3] = "  curl -fsSL " .. releases .. "/download/" .. version .. "/install.sh | sh"
  end
  return table.concat(lines, "\n")
end

-- Hosts whose receiver runs this version.
local checked = {}

-- Remote image cache: policy, host, and source hash -> prepared image hash the host already has.
local sent, sent_count = {}, 0

-- Sends a clipboard image or file to host and returns the receiver's result.
local function transfer(host, remote, ctx, clip)
  -- Regular files are always sent; the receiver still reuses an identical file it already has.
  local key = clip.kind == "image" and table.concat({
    options.resize and options.max_dimension or 0, options.compress and "webp" or "original", host, clip.sha256,
  }, ":")
  if key and sent[key] then
    local hit = call_receiver(remote, {op="lookup", sha256=sent[key], session_id=ctx.session_id, block_id=ctx.block_id})
    if hit and hit.path then return hit end
  end
  local ok, result = pcall(helper, nil, "send", clip.kind, clip.path,
    host, ctx.session_id, ctx.block_id, clip.transfer_id)
  if not ok then
    -- An interrupted helper may still be sending, so only a failed transfer is discarded.
    if type(result) ~= "table" or not result.interrupted then
      pcall(call_receiver, remote, {op="discard", token=clip.transfer_id})
    end
    error(type(result) == "table" and result.message or result, 0)
  end
  if key then
    if sent_count >= 64 then sent, sent_count = {}, 0 end
    if not sent[key] then sent_count = sent_count + 1 end
    sent[key] = result.sha256
  end
  return result
end

-- Whether release tag a, such as "v1.2.3", is newer than b.
local function newer(a, b)
  local x, y = {a:match("^v(%d+)%.(%d+)%.(%d+)$")}, {b:match("^v(%d+)%.(%d+)%.(%d+)$")}
  if #x < 3 or #y < 3 then return false end
  for i = 1, 3 do
    local d = tonumber(x[i]) - tonumber(y[i])
    if d ~= 0 then return d > 0 end
  end
  return false
end

-- Once a week, a release install asks GitHub for the latest release. The request runs in the
-- background, since Rex takes no input while a key-bound action runs, and the next paste shows
-- a notice when that release is newer than this one.
local function check_update(host, ctx)
  if version == "dev" then return end
  local latest = read_line(latest_file)
  if latest then
    os.remove(latest_file)
    if newer(latest, version) and latest ~= read_line(mute_file) then
      notice(host, ctx, table.concat({
        ("rex-paste %s is available (installed %s)."):format(latest, version),
        "Update by running this on the Mac and on every remote host:",
        "  curl -fsSL " .. releases .. "/latest/download/install.sh | sh",
      }, "\n"), latest)
    end
  end
  local last = tonumber(read_line(update_file))
  if last and os.time() - last < 7 * 24 * 3600 then return end
  local f = io.open(update_file, "w")
  if not f then return end
  f:write(os.time(), "\n")
  f:close()
  -- /releases/latest redirects to /releases/tag/<latest>.
  rex.exec.start({"/bin/sh", "-c", 'curl -fsS --max-time 10 -o /dev/null -w "%{redirect_url}" "$1" |'
    .. ' sed -n "s|.*/tag/\\(v[0-9.]*\\)$|\\1|p" >"$2.tmp" && mv "$2.tmp" "$2"',
    "rex-paste", releases .. "/latest", latest_file}, {detach=true, stdout=false, stderr=false})
end

-- Sender: reads the Mac clipboard and pastes text, a local path, or a transferred remote path.
local function paste_clipboard(ctx, host)
  assert(ctx.session_id and ctx.block_id, "rex-paste: select a terminal first")
  local remote = host and rex.server(host)
  local clip = helper(nil, "clipboard")
  if clip.kind == "text" then
    if clip.text ~= "" then paste(remote or rex, ctx, clip.text) end
    return {}
  end
  if not remote then
    -- Regular files paste their original path; images are prepared first.
    local path = clip.kind == "file" and clip.path or helper(nil, "prepare", clip.path).path
    paste(rex, ctx, quoted(path))
    return {path=path}
  end
  -- A host with another version, or none, gets no transfer: the paste fails with a notice.
  local function refuse(problem)
    checked[host] = nil
    pcall(notice, host, ctx, problem)
    error(problem, 0)
  end
  if not checked[host] then
    local problem = receiver_problem(host, remote)
    if problem then refuse(problem) end
    checked[host] = true
  end
  start_pool(host)
  local ok, result = pcall(transfer, host, remote, ctx, clip)
  if not ok then
    -- The host may have been updated since it was checked; a version problem explains the failure.
    local known, problem = pcall(receiver_problem, host, remote)
    if known and problem then refuse(problem) end
    error(result, 0)
  end
  return result
end

function M.setup(opts)
  configure(opts)
  rex.action{name="rex_paste", title="rex-paste: paste clipboard image, file, or text", run=function(ctx)
    local host = ctx.server ~= "" and ctx.server or nil
    local result = paste_clipboard(ctx, host)
    pcall(check_update, host, ctx)
    return result
  end}
  rex.action{name=receive_action, title="rex-paste: receive a transfer (internal)", run=receive}
end

return M
