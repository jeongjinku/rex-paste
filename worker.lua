-- One pooled connection, run by `rex-paste serve` as `rex -S <host> do worker.lua`.
-- Each frame is an 8-digit hex length followed by one client.action request; the reply line
-- says whether it succeeded and whether the receiver needs no more chunks (`done`).
-- Rex's io.lines splits long lines at 4096 bytes, so input is read by length instead.
assert(rex.call("server.status")) -- connect before reporting ready
io.write("READY\n")
io.flush()

while true do
  local header = io.read(8)
  if not header or header == "" then break end
  local size = assert(tonumber(header, 16), "Invalid worker frame")
  local frame = assert(io.read(size))
  assert(size > 0 and #frame == size, "Truncated worker frame")
  local ok, r, err = pcall(rex.call, "client.action", assert(rex.json.decode(frame)))
  if not ok then r, err = nil, r end
  io.write(assert(rex.json.encode({ok=r ~= nil, error=r == nil and tostring(err) or nil,
    done=r and r.result and r.result.done or nil})), "\n")
  io.flush()
  if not r then break end -- the pool replaces this connection
end
return {}
