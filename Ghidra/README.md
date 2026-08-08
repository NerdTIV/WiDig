# WiDig / Ghidra

The Ghidra side of WiDig. There is a Java extension that recognises
both formats on import, and Python scripts that do the symbolisation
afterwards.

An IDA counterpart exists and does the same job, but it is not published yet.
See the note at the end of the top-level README.

```
loader/      Ghidra extension (Java), recognises both formats on import
scripts/     symbolisation, after the import
data/        symbols.json, produced by ghidra_wl.py (not versioned)
tests/       17 checks against real blobs
```

## Requirements

Ghidra 12.x and a JDK 21. For the scripts you also need pyghidra in a venv,
because `analyzeHeadless` will not run a Python script (it answers "not started
with PyGhidra"):

```bash
python3 -m venv ~/ghidra_venv
~/ghidra_venv/bin/pip install pyghidra
```

The blobs are not in the repo, they are proprietary TI binaries. They ship with
`linux-firmware`, so they are already on any machine that drives a WL18xx:

```bash
ls /lib/firmware/ti-connectivity/wl18xx-fw-4.bin
ls /lib/firmware/ti-connectivity/TIInit_11.8.32.bts
```

If you only need the `.bts`, TI publishes them on GitHub:

```bash
git clone --depth 1 https://github.com/TI-ECS/bt-firmware.git
```

## The loader

One `TIWirelessLoaders` extension with two loaders inside:

* `TI WL18xx WiFi firmware (chunked)` for the `wl18xx-fw-*.bin`
* `TI Bluetooth init script (.bts patch)` for the `TIInit_*.bts`

Both set the language to `ARM:LE:32:Cortex`.

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
cd loader && ./build.sh install     # then restart Ghidra
./build.sh clean
```

Built with plain `javac` and `jar`, no gradle. An extension that only provides
loaders needs nothing but Ghidra's jars on the classpath, so the official
gradle build brings nothing except 30 seconds of waiting.

Both loaders sit in the `SPECIALIZED_TARGET_LOADER` tier, so they come ahead of
`Raw Binary` (which accepts anything). Once the extension is installed,
`File > Import` recognises the file on its own.

The loader lays down memory, the Cortex-M vectors, one comment per trace site
and a `trace_<function>` label. Labels go on the call site, not on the function
entry, because at that point the function boundaries do not exist yet.

### Two things that cost me dearly

Ghidra 12 moved to XDG directories. The user folder is now
`~/.config/ghidra/ghidra_<ver>_PUBLIC/`, not the old `~/.ghidra/` any more. If
the extension sits in the old path it gets ignored without a word, and you only
find out when you hit a `ClassNotFoundException`. `build.sh install` detects the
right folder.

And `Module.manifest` has to stay empty. A `MODULE FILE LICENSE:` line pointing
at a missing file makes the module get rejected, silently as well. Two hours for
that one.

## The scripts

```bash
~/ghidra_venv/bin/python scripts/ghidra_wl.py <wl18xx-fw-4.bin> --project /tmp/proj --name WL18xx --export-symbols data/symbols.json

~/ghidra_venv/bin/python scripts/ghidra_bts.py <TIInit_11.8.32.bts> --project /tmp/proj --name BT_patch --outdir /tmp/bt_patch
```

`ghidra_wl.py` runs through 9 steps: memory map, vectors, disassembly plus a
Thumb prologue scan, symbolisation from the traces, grouping by source file,
collecting the MMIO registers then materialising them as blocks, trace helpers,
and attaching the anonymous functions using the call graph.

What that gives on `wl18xx-fw-4.bin`: 435 functions named out of the 450
available, 437 grouped into 82 modules, 358 MMIO registers labelled, 816
anonymous functions attached to a module. Careful with that last number, the
prefix says "called from", not "defined in".

`--export-symbols` writes all of it into a JSON. That file is what the IDA side
replays as is, so both tools end up showing the same thing. It is also just a
readable dump of everything the run recovered, if you want to use it elsewhere.

## Tests

```bash
~/ghidra_venv/bin/python tests/test_loaders.py --blobs <blob folder>
```

17 checks, 0 failure. It checks that the loader claims the file, that it comes
ahead of Raw Binary, that it lays down the right memory map, and above all that
it rejects `wl18xx-conf.bin` and a plain ELF. Rejecting is half of a loader's
job, a greedy loader ruins everybody else's import dialog.

Two things to know before running it. You need to have done `./build.sh install`
and restarted Ghidra, otherwise all 17 fail at once. And `--blobs` has to point
at a folder that really contains `wl18xx-fw-4.bin` and `TIInit_11.8.32.bts`. The
blobs are not in the repo, so without them the tests that need them are skipped
cleanly and only one is left, the ELF rejection. That is expected, it is not a
failure.
