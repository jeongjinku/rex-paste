# rex-paste

- Zig code targets Zig 0.17.0: follow `.claude/skills/zig-0-17/SKILL.md`.
- Lua code runs in Rex's Lua 5.1 runtime, so `.claude/skills/lua-guide/SKILL.md` applies except
  for its Lua 5.4 features: no `//`, `<const>`, `math.type`, or `utf8` library.
- Code, comments, and docs are in English.
- Lint Lua with `luacheck .`. Tests: `sh build.sh`, `python3 test/binary_test.py`, `sh test/clipboard_test.sh` (macOS),
  `rex do test/actions_test.lua`.
