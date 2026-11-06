"""Receive, validation, and pool tests for the real binary: python3 test/binary_test.py. Never touches the clipboard."""
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
import unittest
import uuid
import zlib

# Tests bin/rex-paste from `sh build.sh`. Receiver tests run everywhere; sender tests need macOS.
BINARY = Path(__file__).resolve().parent.parent / "bin/rex-paste"
CHUNK = 45056


def png(width, height):
    raw = b"".join(b"\x00" + bytes([x % 256, 64, 128]) * width for x in range(height))
    chunk = lambda kind, body: (struct.pack(">I", len(body)) + kind + body
                                + struct.pack(">I", zlib.crc32(kind + body)))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.env = dict(os.environ, HOME=self.tmp.name)
        self.root = Path(self.tmp.name) / ".cache/rex-paste/v2"
        self.data = b"\x89PNG\r\n\x1a\n" + os.urandom(CHUNK * 3)

    def call(self, op, *args, payload=None, ok=True):
        r = subprocess.run([str(BINARY), op, *args], input=json.dumps(payload) if payload else None,
                           capture_output=True, text=True, env=self.env)
        if ok:
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout)
        self.assertNotEqual(r.returncode, 0)
        return r

    def payloads(self):
        return self.file_payloads(self.data, None)

    def test_parallel_reverse_and_duplicate(self):
        chunks = self.payloads()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda p: self.call("push", payload=p), list(reversed(chunks)) * 2))
        paths = [r["path"] for r in results if r["path"]]
        self.assertEqual(len(paths), 1)
        path = Path(paths[0])
        self.assertEqual(path.read_bytes(), self.data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.call("discard", chunks[0]["token"])
        # A separate transfer reuses the verified remote cache on the first chunk.
        p = self.payloads()[0]
        self.assertEqual(self.call("push", payload=p)["path"], str(path))

    def test_cleanup_keeps_used_entries(self):
        # cleanup removes entries unused for a day; a lookup that pastes an old entry renews it.
        used, unused = png(3, 3), png(5, 5)
        paths = {}
        for data in (used, unused):
            chunks = self.file_payloads(data, None)
            paths[data] = Path([self.call("push", payload=p)["path"] for p in chunks][-1])
        old = time.time() - 2 * 24 * 3600
        for path in paths.values():
            os.utime(path, (old, old))
        self.assertEqual(self.call("lookup", hashlib.sha256(used).hexdigest())["path"], str(paths[used]))
        self.call("push", payload=self.payloads()[0])  # a new transfer's first chunk runs cleanup
        self.assertTrue(paths[used].exists())
        self.assertFalse(paths[unused].exists())

    def test_missing_and_corrupted(self):
        chunks = self.payloads()
        for p in chunks[:-1]:
            self.assertIsNone(self.call("push", payload=p)["path"])
        self.assertFalse(list(self.root.glob("*.png")))
        p = chunks[-1]
        p["data"] = base64.b64encode(b"X" * len(base64.b64decode(p["data"]))).decode()
        self.call("push", payload=p, ok=False)
        self.assertFalse(list(self.root.glob("*.png")))

    def test_bounds_conflict_and_symlink(self):
        p = self.payloads()[0]
        for changes in ({"offset":1}, {"size":0}, {"size":16 * 1024 * 1024 + 1}, {"token":"../x"}, {"data":"@@@"}):
            self.call("push", payload=dict(p, **changes), ok=False)
        self.call("push", payload=p)
        self.call("push", payload=dict(p, sha256="0"*64), ok=False)
        outside = Path(self.tmp.name) / "outside"
        outside.write_bytes(b"safe")
        p = self.payloads()[0]
        (self.root / (p["token"] + ".state")).symlink_to(outside)
        self.call("push", payload=p, ok=False)
        self.assertEqual(outside.read_bytes(), b"safe")

    def file_payloads(self, data, name):
        token = uuid.uuid4().hex
        return [dict(token=token, size=len(data), sha256=hashlib.sha256(data).hexdigest(), name=name,
                     offset=i, data=base64.b64encode(data[i:i+CHUNK]).decode())
                for i in range(0, len(data), CHUNK)]

    def test_raw_file_16mib(self):
        # Regular files keep their name and bytes up to the 16MiB default limit.
        data = os.urandom(16 * 1024 * 1024)
        chunks = self.file_payloads(data, "résumé 'final'.pdf")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda p: self.call("push", payload=p), reversed(chunks)))
        paths = [r["path"] for r in results if r["path"]]
        self.assertEqual(len(paths), 1)
        path = Path(paths[0])
        self.assertEqual(path, self.root / hashlib.sha256(data).hexdigest() / "résumé 'final'.pdf")
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        # Resending the same file returns the verified existing file on the first chunk, and
        # tells the sender to stop; so does every later chunk.
        again = self.file_payloads(data, "résumé 'final'.pdf")
        self.assertEqual(self.call("push", payload=again[0]), {"path": str(path), "done": True})
        self.assertEqual(self.call("push", payload=again[1]), {"path": None, "done": True})

    def test_concurrent_first_chunks(self):
        # A transfer's first chunks arrive together, one per pool connection, and all create the
        # state file. macOS failed some of those opens with FileNotFound.
        data = os.urandom(CHUNK * 12)
        for _ in range(30):
            procs = []
            for p in self.file_payloads(data, "race.bin"):
                procs.append(subprocess.Popen([str(BINARY), "push"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, env=self.env))
                procs[-1].payload = json.dumps(p).encode()
            for proc in procs:  # released together, once every process is waiting on its stdin
                proc.stdin.write(proc.payload)
            for proc in procs:
                proc.stdin.close()
            for proc in procs:
                _, err = proc.communicate()
                self.assertEqual(proc.returncode, 0, err.decode())

    def test_progress(self):
        # Pushes ask for the progress float once the transfer has run over a second.
        data = os.urandom(CHUNK * 4)
        chunks = self.file_payloads(data, "big.bin")
        watcher = subprocess.Popen([str(BINARY), "progress", chunks[0]["token"], "big.bin"], stdout=subprocess.PIPE,
                                   env=self.env)
        self.assertIsNone(self.call("push", payload=chunks[0])["progress"])
        time.sleep(1.1)
        self.assertIsNone(watcher.poll())
        width = self.call("push", payload=chunks[1])["progress"]
        self.assertIsNone(self.call("push", payload=chunks[2])["progress"])
        self.assertIsNotNone(self.call("push", payload=chunks[3])["path"])
        out, _ = watcher.communicate(timeout=5)
        self.assertEqual(watcher.returncode, 0)
        frames = [f.replace("\x1b[36m", "").replace("\x1b[90m", "").replace("\x1b[0m", "")
                  for f in out.decode().split("\r")[1:]]
        self.assertEqual(frames[0], "big.bin  " + "█" * 5 + "░" * 15 + "  25%  0.0 / 0.2 MiB")
        self.assertEqual(frames[-1], "big.bin  " + "█" * 20 + " 100%  0.2 / 0.2 MiB")
        self.assertEqual(width, len(frames[-1]) + 2)  # the float's width, with two spare columns
        # The last chunk's bit is saved before the file is verified, so the watcher can draw 100%
        # before the transfer is done. It still ends once the transfer is.
        chunks = self.file_payloads(data, "slow.bin")
        watcher = subprocess.Popen([str(BINARY), "progress", chunks[0]["token"], "slow.bin"],
                                   stdout=subprocess.DEVNULL, env=self.env)
        for p in chunks[:3]:
            self.call("push", payload=p)
        state = self.root / (chunks[0]["token"] + ".state")
        raw = bytearray(state.read_bytes())
        raw[44] |= 1 << 3  # the bitmap follows the 44-byte header
        state.write_bytes(raw)
        time.sleep(0.3)
        self.assertIsNotNone(self.call("push", payload=chunks[3])["path"])
        self.assertEqual(watcher.wait(timeout=5), 0)
        # A discarded transfer ends it too.
        chunks = self.file_payloads(data, "gone.bin")
        watcher = subprocess.Popen([str(BINARY), "progress", chunks[0]["token"], "gone.bin"],
                                   stdout=subprocess.DEVNULL, env=self.env)
        self.call("push", payload=chunks[0])
        time.sleep(0.3)
        self.call("discard", chunks[0]["token"])
        self.assertEqual(watcher.wait(timeout=5), 0)

    def test_raw_file_bounds(self):
        p = self.file_payloads(b"plain text", "a.txt")[0]
        for name in ("", ".", "..", "a/b", "../x", "a\nb", "x" * 256):
            self.call("push", payload=dict(p, name=name), ok=False)
        big = self.file_payloads(os.urandom(CHUNK), "big.bin")[0]
        self.call("push", payload=dict(big, size=16 * 1024 * 1024), ok=True)
        self.call("push", payload=dict(big, token=uuid.uuid4().hex, size=16 * 1024 * 1024 + 1), ok=False)
        self.assertIsNotNone(self.call("push", payload=p)["path"])

    def test_max_size_setting(self):
        # One size limit covers images and files, and setup{max_size=...} lowers or raises it.
        self.env["REX_PASTE_MAX_SIZE"] = str(CHUNK * 2)
        image = self.payloads()[0]
        self.call("push", payload=image, ok=False)
        data = os.urandom(CHUNK * 2)
        self.assertIsNone(self.call("push", payload=self.file_payloads(data, "fits.bin")[0])["path"])  # accepted, incomplete
        self.call("push", payload=self.file_payloads(data + b"x", "over.bin")[0], ok=False)
        self.env["REX_PASTE_MAX_SIZE"] = "0"
        self.call("push", payload=image, ok=False)

    def test_receiver_keeps_image_format(self):
        # compress=false sends JPEG/HEIC/TIFF/GIF as images; the receiver names them by signature.
        for head, ext in ((b"\xff\xd8\xff\xe0", ".jpg"), (b"II*\x00", ".tiff"), (b"GIF89a", ".gif"),
                          (b"\x00\x00\x00\x18ftypheic", ".heic")):
            self.data = head + os.urandom(100)
            path = self.call("push", payload=self.payloads()[0])["path"]
            self.assertTrue(path.endswith(ext), path)
            self.assertEqual(Path(path).read_bytes(), self.data)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sender")
    def test_compress_off_keeps_format(self):
        small, large = Path(self.tmp.name) / "small.png", Path(self.tmp.name) / "large.png"
        small.write_bytes(png(40, 20)); large.write_bytes(png(2100, 30))
        jpeg = Path(self.tmp.name) / "large.jpg"
        subprocess.run(["sips", "-s", "format", "jpeg", str(large), "--out", str(jpeg)], check=True, capture_output=True)
        self.env["REX_PASTE_COMPRESS"] = "0"
        # Within the bound: the original bytes, unchanged.
        self.assertEqual(Path(self.call("prepare", str(small))["path"]).read_bytes(), small.read_bytes())
        # Over the bound: resized, same format.
        for source, ext, magic in ((large, ".png", b"\x89PNG"), (jpeg, ".jpg", b"\xff\xd8\xff")):
            out = Path(self.call("prepare", str(source))["path"])
            self.assertEqual(out.suffix, ext)
            self.assertTrue(out.read_bytes().startswith(magic))
            width = subprocess.run(["sips", "-g", "pixelWidth", str(out)], capture_output=True, text=True).stdout.split()[-1]
            self.assertEqual(width, "2000")
        # Resize off too: even the large JPEG goes out unchanged.
        self.env["REX_PASTE_RESIZE"] = "0"
        self.assertEqual(Path(self.call("prepare", str(jpeg))["path"]).read_bytes(), jpeg.read_bytes())
        # Formats receivers cannot recognize, such as BMP, still become WebP.
        bmp = Path(self.tmp.name) / "small.bmp"
        subprocess.run(["sips", "-s", "format", "bmp", str(small), "--out", str(bmp)], check=True, capture_output=True)
        self.assertEqual(Path(self.call("prepare", str(bmp))["path"]).suffix, ".webp")

    def rex_cli(self):
        return str(Path(self.tmp.name) / ".local/bin/rex")

    def write_rex(self, script):
        worker = Path(self.rex_cli())
        worker.parent.mkdir(parents=True, exist_ok=True)
        worker.write_text(script)
        worker.chmod(0o700)

    def serve(self, host, **env):
        pool = subprocess.Popen([str(BINARY), "serve", self.rex_cli(), host, str(os.getpid())],
                                env=dict(self.env, **env), stdout=subprocess.DEVNULL)
        self.addCleanup(lambda: (pool.poll() is None and pool.kill(), pool.wait()))
        return pool

    @staticmethod
    def ids():
        return "session:test", "block:test", uuid.uuid4().hex

    def pool_rex(self, host, stall_once=False, refuse=False):
        # A fake `rex do worker.lua` that hands each chunk to `push` under a separate remote
        # HOME and replies with its `done`, as worker.lua does. With stall_once, the first
        # connection answers READY and then stops reading. With refuse, the host fails every chunk.
        remote = Path(self.tmp.name) / "remote"
        remote.mkdir(exist_ok=True)
        self.write_rex(f"""#!{sys.executable}
import json, os, subprocess, sys, time
assert sys.argv[1:6] == ["--timeout", "10s", "-S", {host!r}, "do"], sys.argv
print("READY", flush=True)
if {stall_once!r}:
    try:
        os.close(os.open({str(remote / "stalled")!r}, os.O_CREAT | os.O_EXCL))
        time.sleep(120)
    except FileExistsError:
        pass
env = dict(os.environ, HOME={str(remote)!r})
while header := sys.stdin.buffer.read(8):
    request = json.loads(sys.stdin.buffer.read(int(header, 16)))
    assert request["action"] == "rex_paste_receive"
    if {refuse!r}:
        print(json.dumps({{"ok": False, "error": "simulated refusal"}}), flush=True)
        break
    r = subprocess.run([{str(BINARY)!r}, "push"], input=json.dumps(request["args"]).encode(), env=env, check=True, capture_output=True)
    with open({str(remote / "pushes")!r}, "a") as log:
        log.write("x")
    print(json.dumps({{"ok": True, "done": json.loads(r.stdout).get("done", False)}}), flush=True)
""")
        return remote

    @unittest.skipUnless(sys.platform == "darwin", "macOS sender")
    def test_send_through_pool(self):
        # A fake `rex do worker.lua` hands each chunk to `push` under a separate remote HOME,
        # so the pool, the socket client, the chunk JSON, and reassembly run without Rex.
        remote = self.pool_rex("pool-test")
        self.env["REX_PASTE_CONNECTIONS"] = "2"  # the client finds the pool by its settings
        pool = self.serve("pool-test")
        data = os.urandom(CHUNK * 5 + 7)
        source = Path(self.tmp.name) / "report 'v2'.bin"
        source.write_bytes(data)
        result = self.call("send", "file", str(source), "pool-test", *self.ids())
        self.assertTrue(result["ok"])
        sha = hashlib.sha256(data).hexdigest()
        self.assertEqual(result["sha256"], sha)
        self.assertEqual((remote / ".cache/rex-paste/v2" / sha / source.name).read_bytes(), data)
        # Images are prepared first; the pool sends the prepared WebP.
        image = Path(self.tmp.name) / "image.png"
        image.write_bytes(png(40, 20))
        result = self.call("send", "image", str(image), "pool-test", *self.ids())
        webp = remote / ".cache/rex-paste/v2" / (result["sha256"] + ".webp")
        self.assertTrue(webp.read_bytes().startswith(b"RIFF"))
        # A failed read fails only that request; the pool keeps serving.
        self.call("send", "file", str(Path(self.tmp.name) / "missing"), "pool-test", *self.ids(), ok=False)
        (Path(self.tmp.name) / "empty").write_bytes(b"")
        self.call("send", "file", str(Path(self.tmp.name) / "empty"), "pool-test", *self.ids(), ok=False)
        # A file the host already has stops once the first chunks report it, not after all six.
        (remote / "pushes").write_text("")
        self.assertTrue(self.call("send", "file", str(source), "pool-test", *self.ids())["ok"])
        self.assertLessEqual(len((remote / "pushes").read_text()), 2)
        self.assertIsNone(pool.poll())

    @unittest.skipUnless(sys.platform == "darwin", "macOS sender")
    def test_pool_replaced_when_settings_change(self):
        # Workers answer READY, then stop reading and ignore SIGTERM.
        self.write_rex(f"#!{sys.executable}\nimport signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nprint('READY',flush=True)\ntime.sleep(120)\n")
        host = "settings-test"
        lock = self.root / ("pool-" + hashlib.sha256(host.encode()).hexdigest()[:16] + ".lock")
        start = lambda connections: self.serve(host, REX_PASTE_CONNECTIONS=str(connections))
        def recorded():
            for _ in range(500):
                if lock.exists() and lock.read_text().strip():
                    return lock.read_text().split()
                time.sleep(.01)
            self.fail("pool did not record its settings")
        # The binary's mtime stands for its version, so a rebuilt binary also replaces the pool.
        binary = str(BINARY.stat().st_mtime_ns)
        first = start(2)
        self.assertEqual(recorded(), [str(first.pid), "2", str(16 * 1024 * 1024), binary])
        same = start(2)
        self.assertEqual(same.wait(timeout=5), 0)  # same settings: the running pool stays
        self.assertIsNone(first.poll())
        second = start(3)
        first.wait(timeout=5)  # other settings: the old pool is replaced
        for _ in range(500):
            if recorded()[0] == str(second.pid):
                break
            time.sleep(.01)
        self.assertEqual(recorded(), [str(second.pid), "3", str(16 * 1024 * 1024), binary])

    @unittest.skipUnless(sys.platform == "darwin", "macOS sender")
    def test_stalled_connection_is_replaced(self):
        # One connection stops reading mid-transfer: it times out, its chunk goes back to the
        # queue, and the transfer completes. The pool keeps serving.
        remote = self.pool_rex("stalled-test", stall_once=True)
        data = os.urandom(CHUNK * 4)
        source = Path(self.tmp.name) / "big.bin"
        source.write_bytes(data)
        self.env["REX_PASTE_CONNECTIONS"] = "2"  # the client finds the pool by its settings
        pool = self.serve("stalled-test")
        result = self.call("send", "file", str(source), "stalled-test", *self.ids())
        sha = hashlib.sha256(data).hexdigest()
        self.assertEqual(result["sha256"], sha)
        self.assertEqual((remote / ".cache/rex-paste/v2" / sha / source.name).read_bytes(), data)
        self.assertIn("WorkerTimeout); resending", self.pool_log())
        self.assertTrue(self.call("send", "file", str(source), "stalled-test", *self.ids())["ok"])
        self.assertIsNone(pool.poll())

    @unittest.skipUnless(sys.platform == "darwin", "macOS sender")
    def test_chunk_that_fails_twice(self):
        # A chunk is sent once more on another connection; failing again fails the transfer
        # with the host's reason, and the pool keeps serving.
        self.pool_rex("refusing-test", refuse=True)
        self.env["REX_PASTE_CONNECTIONS"] = "2"
        pool = self.serve("refusing-test")
        source = Path(self.tmp.name) / "a.bin"
        source.write_bytes(os.urandom(CHUNK * 3))
        r = self.call("send", "file", str(source), "refusing-test", *self.ids(), ok=False)
        self.assertIn("simulated refusal", r.stderr)
        self.assertIn("resending chunk", self.pool_log())
        self.assertIsNone(pool.poll())

    def pool_log(self):
        log = Path(self.tmp.name) / ".cache/rex-paste/pool.log"
        return log.read_text() if log.exists() else ""

    @unittest.skipUnless(sys.platform == "darwin", "macOS sender")
    def test_pool_that_cannot_connect(self):
        # Workers whose rex CLI cannot reach the host: the paste says where the reason is, and
        # the pool's log has the CLI's own error.
        self.write_rex("#!/bin/sh\nsleep 0.5\necho 'rex: cannot reach far-host' >&2\nexit 1\n")
        self.env["REX_PASTE_CONNECTIONS"] = "2"  # the client finds the pool by its settings
        pool = self.serve("far-host")
        source = Path(self.tmp.name) / "a.bin"
        source.write_bytes(b"data")
        r = self.call("send", "file", str(source), "far-host", *self.ids(), ok=False)
        self.assertIn("PoolUnavailable", r.stderr)
        self.assertIn(".cache/rex-paste/pool.log", r.stderr)
        self.assertEqual(pool.wait(timeout=10), 1)
        self.assertIn("rex: cannot reach far-host", self.pool_log())
        self.assertIn("WorkerNotReady", self.pool_log())


if __name__ == "__main__":
    unittest.main()
