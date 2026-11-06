-- Waits for an update notice to close, run detached on the Mac by init.lua as
--   rex [-S <host>] do -s <session> notice.lua --args '{"block":..., "mute_file":..., "mute_text":...}'
-- The notice's program exits with 1 when n is pressed, which writes mute_text to mute_file.
local args = rex.args
local ev = rex.wait("terminal.child_exited", {block_id=args.block}, 3600)
if ev and ev.exit_code == 1 then
  local f = io.open(args.mute_file, "w")
  if f then
    f:write(args.mute_text, "\n")
    f:close()
  end
end
return {}
