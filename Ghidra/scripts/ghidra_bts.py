#!/usr/bin/env python3
"""
Charge dans Ghidra le patch de code BT extrait d'un TIInit_*.bts.

Le .bts c'est pas un firmware, c'est la sequence HCI qu'on rejoue au boot.
Le code du coeur BT voyage dans les commandes vendor 0xff05, que TI appelle
HCI_VS_Write_Memory_Block (addr u32 le | len u8 | data). Les 0xff03 sont des
ecritures ponctuelles.

    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
    /opt/ghidra_venv/bin/python ghidra_bts.py /chemin/TIInit_11.8.32.bts --project /tmp/ghidra_proj --name BT_patch

--dump-only ecrit juste les blobs sur disque, pratique quand Ghidra est pas
dispo.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wl_fw

# headless via pyghidra, ou Script Manager du GUI
IN_GHIDRA = 'currentProgram' in globals()
DEFAULT_BTS = '/lib/firmware/ti-connectivity/TIInit_11.8.32.bts'


def addr_of(program, value):
    space = program.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress('%x' % value)


def tri_par_taille(blobs):
    """Du plus gros au plus petit."""
    tmp = []
    for addr, data in blobs:
        tmp.append((len(data), addr, data))
    tmp.sort(reverse=True)
    out = []
    for _n, addr, data in tmp:
        out.append((addr, data))
    return out


def dump_blobs(bts, outdir):
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    written = []
    for addr, data in bts.patch_blobs():
        path = os.path.join(outdir, 'bt_patch_%08x.bin' % addr)
        with open(path, 'wb') as f:
            f.write(data)
        written.append((path, addr, len(data)))
    return written


def run(flat, program, bts, blobs):
    """Charge les blobs et etiquette les pokes."""
    from ghidra.program.model.symbol import SourceType
    from java.io import ByteArrayInputStream

    mem = program.getMemory()
    fm = program.getFunctionManager()
    monitor = flat.getMonitor()

    for block in list(mem.getBlocks()):
        mem.removeBlock(block, monitor)
    for addr, data in blobs:
        block = mem.createInitializedBlock(
            'patch_%08x' % addr, addr_of(program, addr),
            ByteArrayInputStream(data), len(data), monitor, False)
        block.setRead(True)
        block.setWrite(True)
        block.setExecute(True)
    print('[1] %d blocs de patch charges' % len(blobs))

    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(monitor)

    # meme scan de prologues que dans ghidra_wl.py. Pas factorise, les deux
    # scripts doivent pouvoir tourner l'un sans l'autre.
    created = 0
    for addr, data in blobs:
        for off in range(0, len(data) - 1, 2):
            if not (data[off + 1] == 0xb5
                    or (data[off] == 0x2d and data[off + 1] == 0xe9)):
                continue
            target = addr_of(program, addr + off)
            if fm.getFunctionContaining(target) is not None:
                continue
            try:
                flat.disassemble(target)
                if fm.getFunctionAt(target) is None:
                    flat.createFunction(target, None)
                if fm.getFunctionAt(target) is not None:
                    created += 1
            except Exception:
                continue
    print('[2] fonctions creees par scan de prologues : %d' % created)

    st = program.getSymbolTable()
    listing = program.getListing()
    poked = 0
    for addr, value in bts.pokes():
        try:
            target = addr_of(program, addr)
            st.createLabel(target, 'bts_poke_%08x' % addr,
                           SourceType.USER_DEFINED)
            hexval = ''.join('%02x' % (b if isinstance(b, int) else ord(b))
                             for b in value)
            listing.setComment(target, 0,
                               'ecrit par TIInit au boot : 0x%s' % hexval)
            poked += 1
        except Exception:
            pass
    print('[3] adresses ecrites par le script BT etiquetees : %d' % poked)


def main_gui():
    """Script Manager: partir d'une base vide en ARM:LE:32:Cortex."""
    from ghidra.program.flatapi import FlatProgramAPI

    path = os.environ.get('WL_BTS')
    if not path:
        try:
            path = askFile('script TIInit_*.bts', 'Choisir').getAbsolutePath()
        except Exception:
            path = DEFAULT_BTS
    bts = wl_fw.BtsScript(path)
    bts.report()
    blobs = []
    for addr, data in bts.patch_blobs():
        if len(data) >= 256:
            blobs.append((addr, data))
    blobs = tri_par_taille(blobs)
    run(FlatProgramAPI(currentProgram), currentProgram, bts, blobs)
    print('=== fini ===')


def main_headless():
    ap = argparse.ArgumentParser()
    ap.add_argument('bts')
    ap.add_argument('--project', default='/tmp/ghidra_proj')
    ap.add_argument('--name', default='BT_patch')
    ap.add_argument('--outdir', default='/tmp/bt_patch')
    ap.add_argument('--dump-only', action='store_true')
    ap.add_argument('--min-size', type=int, default=256,
                    help='ignore les blobs plus petits, c est du poke isole')
    args = ap.parse_args()

    bts = wl_fw.BtsScript(args.bts)
    bts.report()

    written = dump_blobs(bts, args.outdir)
    print('\n[+] %d blobs ecrits dans %s' % (len(written), args.outdir))
    if args.dump_only:
        return 0

    blobs = []
    for addr, data in bts.patch_blobs():
        if len(data) >= args.min_size:
            blobs.append((addr, data))
    if not blobs:
        print('[!] aucun blob assez gros pour valoir un desassemblage')
        return 1

    # le plus gros blob devient le programme, les autres seront des blocs
    blobs = tri_par_taille(blobs)
    main_addr, main_data = blobs[0]
    main_path = os.path.join(args.outdir, 'bt_patch_%08x.bin' % main_addr)
    print('[*] programme principal : blob 0x%08x (%d octets)'
          % (main_addr, len(main_data)))

    import pyghidra
    pyghidra.start()

    from ghidra.program.model.symbol import SourceType
    from java.io import ByteArrayInputStream

    with pyghidra.open_program(main_path,
                               project_location=args.project,
                               project_name=args.name,
                               analyze=False,
                               language='ARM:LE:32:Cortex',
                               loader='ghidra.app.util.opinion.BinaryLoader') as flat:
        program = flat.getCurrentProgram()
        mem = program.getMemory()
        fm = program.getFunctionManager()
        monitor = flat.getMonitor()

        tx = program.startTransaction('chargement patch BT')
        try:
            run(flat, program, bts, blobs)
        finally:
            program.endTransaction(tx, True)
    print('\n=== termine, projet dans %s/%s ===' % (args.project, args.name))
    return 0


def main():
    if IN_GHIDRA:
        main_gui()
        return 0
    return main_headless()


if __name__ == '__main__':
    sys.exit(main())
