# WiDig

Digging symbols out of TI WiLink firmware, for Ghidra and IDA.

The WL18xx is a TI radio combo you find on a lot of embedded Linux boards.
WiFi plus a Bluetooth controller (`hci0`), running on a Cortex-M core in Thumb.
TI documents none of it, but they shipped the firmware with its debug trace
database still in place. WiDig starts from that and works out the rest.

The tooling targets the WL18xx, but the chunked container belongs to the
`wlcore` driver and not to the chip itself. So it works on the older
generations too, and it should keep working on the next ones as long as TI
sticks to the same format.

## Install

```bash
git clone https://github.com/NerdTIV/WiDig
cd WiDig/Ghidra/loader
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
./build.sh install
```

Restart Ghidra. Needs Ghidra 12.x, a JDK 21, and `zip`, which build.sh uses to
pack the extension. No gradle, no Eclipse.

## Use it

Open a `wl18xx-fw-*.bin` or a `TIInit_*.bts` in Ghidra. The importer recognises
it on its own and offers `TI WL18xx WiFi firmware (chunked)` or `TI Bluetooth
init script (.bts patch)`. Memory map, Cortex-M vectors and trace labels are
laid down at import.

Then, for the naming pass, pyghidra in a venv (`analyzeHeadless` refuses to run
Python scripts):

```bash
python3 -m venv ~/ghidra_venv
~/ghidra_venv/bin/pip install pyghidra

~/ghidra_venv/bin/python Ghidra/scripts/ghidra_wl.py wl18xx-fw-4.bin --project /tmp/proj --name WL18xx
```

435 of the 450 available functions come back named, grouped into 82 source
modules. `Ghidra/README.md` covers the rest: the `.bts` script, the symbol
export, and the tests.

## What it accepts, measured

Tested against the 18 TI firmwares shipped in `linux-firmware`: 16 accepted.
The corpus is not in the repo (proprietary TI binaries), see below to grab it.

`wl18xx-fw-2/3/4` (WiLink8) have 15 chunks and carry a trace database, with 497,
586 and 963 traces respectively. The first-generation `wl18xx-fw` also has 15
chunks but no trace database at all.

`wl127x`, `wl128x` and `wl1271` (WiLink6-7) have 6 chunks, and only carry traces
in `fw-5`, mostly in the `-mr` builds.

`wl1251` (WiLink4) and `cc33xx` get rejected, they use a different container.

The trace database depends on the build, not on the chip. It shows up in `fw-2`
on WiLink8, in `fw-5` on WiLink6-7, and the `-mr` (multi-role) builds keep
around 25 times more of them than the `-sr` (single-role) ones.

When there is no trace database, the loader still lays down the memory map and
the vectors. That is the hard part, and the part without which nothing
disassembles at all. You only lose the symbols.

```
WiDig/
└── Ghidra/     loader (Java extension) + symbolisation scripts + tests
```

### About the IDA side

There is an IDA counterpart, with the same loaders written in IDAPython and the
same symbolisation. It is **not in this repo yet**, and that is deliberate.

I have no IDA licence on this machine, so it has never actually run for real.
It is validated against a fake in-memory IDA kernel, which proves the logic
holds but says nothing about how the real disassembler behaves. Publishing it
would mean shipping something I cannot honestly claim works.

It will land here as `IDA/` once I can check it against a licensed IDA. Both
sides are meant to do the same job on the same blobs and produce the same
numbers, so a gap between them will be a bug, not a difference between tools.

The regression test that sweeps the whole 18-firmware corpus lives on that
side too, and will come with it.

## If you do not have a blob yet

The normal case is that you already dumped a chip, or already have the binary
in hand. Point the loader at it and skip this section.

If you just want to try the tooling on something, the firmware is not shipped
here (proprietary TI binaries) but it comes with `linux-firmware`, so it is
already sitting on any machine that drives a WL18xx:

```bash
ls -l /lib/firmware/ti-connectivity/
#   wl18xx-fw-4.bin        746 KB   WiFi firmware
#   TIInit_11.8.32.bts      75 KB   Bluetooth init script
#   wl18xx-conf.bin        1.2 KB   config (not handled)
```

TI also publishes the `.bts` files on GitHub, handier if you only care about
the Bluetooth side:

```bash
git clone --depth 1 https://github.com/TI-ECS/bt-firmware.git
ls bt-firmware/TIInit_11.8.32.bts
```

And out of a disk image, without mounting anything or going root:

```bash
debugfs -R "dump /lib/firmware/ti-connectivity/wl18xx-fw-4.bin ./wl18xx-fw-4.bin" rootfs.ext4
```

## The two formats

`wl18xx-fw-4.bin` is not a flat image. It is a list of chunks prefixed with
address and size in big-endian, exactly the way `wlcore/boot.c` reads it on the
driver side:

```
u32 be  chunk count
per chunk : u32 be address | u32 be size | <size bytes>
```

15 chunks, from `0x00000000` up to `0x80960000`. Chunk 0 starts with a Cortex-M
vector table (initial SP `0x20401594`, reset handler `0x0001bd8d`, odd so
Thumb).

And glued to the end of the file, the `GTRACEBINMAGICHDR` trace database:

```
<address>,<line>,<file.c>,<function>,<nargs>|<printf format>
```

963 traces, 450 function names, 85 source files. That is a de facto symbol
table for a proprietary firmware, and it is the whole point of this target.

`TIInit_11.8.32.bts` is not a firmware either, it is the HCI sequence replayed
at boot. A `BTSB` header then 747 actions. The `0xff05` vendor commands, which
TI calls `HCI_VS_Write_Memory_Block` (265 of them), carry the BT core code in
240-byte pieces, glued back together that gives 11 blobs. The `0xff03` ones (32
of them) are one-off memory writes.

## Numbers you should get

On `wl18xx-fw-4.bin`: 15 chunks loaded, 19 Cortex-M vectors, 440 trace labels
placed by the loader. On the `.bts`: 11 patch blobs and 32 `0xff03` pokes
labelled.

The symbolisation script names 435 functions out of the 450 available in the
trace database, with 93% and 85% coverage on the two code chunks.
