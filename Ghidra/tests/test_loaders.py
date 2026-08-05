#!/usr/bin/env python3
"""
Teste le loader TIWirelessLoaders en headless.

    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
    /opt/ghidra_venv/bin/python tests/test_loaders.py --blobs <dossier>

Faut que l'extension soit installee et Ghidra redemarre avant, sinon tout
echoue et on comprend rien:
    cd ../loader && ./build.sh install

Ce que je verifie: que le loader se declare tout seul sur le fichier et passe
devant Raw Binary, qu'il se declare PAS sur un fichier d'un autre format, et
que la carte memoire posee est la bonne.

C'est ca qui separe un loader d'un script: personne va choisir
"Raw Binary / ARM:LE:32:Cortex / base 0" a la main dans le dialogue d'import.

Pas de pytest, ca vaut pas le coup pour 17 assertions et ca ferait une
dependance de plus dans le venv Ghidra.
"""

import argparse
import os
import sys

PROJECT = '/tmp/ghidra_wl_loader_test'
RESULTS = []


def check(label, ok, detail=''):
    RESULTS.append((label, bool(ok), detail))
    print('  %-5s %s%s' % ('OK' if ok else 'ECHEC', label,
                           ('   (%s)' % detail) if detail else ''))
    return bool(ok)


def loaders_for(path):
    """Les loaders qui acceptent ce fichier, du plus prioritaire au moins."""
    from ghidra.app.util.bin import FileByteProvider
    from ghidra.app.util.opinion import LoaderService
    from java.io import File
    from java.nio.file import AccessMode

    provider = FileByteProvider(File(path), None, AccessMode.READ)
    try:
        # LoaderMap = Map<Loader, Collection<LoadSpec>>, trie par priorite
        loader_map = LoaderService.getAllSupportedLoadSpecs(provider)
        out = []
        for loader in loader_map.keySet():
            for spec in loader_map.get(loader):
                lang = spec.getLanguageCompilerSpec()
                out.append((loader.getName(),
                            str(lang.languageID) if lang else '?'))
        return out
    finally:
        provider.close()


def blocks_of(program):
    return [(b.getName(), b.getStart().getOffset(), b.getSize())
            for b in program.getMemory().getBlocks()]


def test_firmware(path):
    print('\n[1] firmware WiFi wl18xx-fw-*.bin')
    ordered = loaders_for(path)
    names = [n for n, _ in ordered]
    check('le loader se declare', 'TI WiLink firmware (chunked)' in names,
          ', '.join(names[:3]))
    check('il passe devant Raw Binary',
          names and names[0] == 'TI WiLink firmware (chunked)',
          names[0] if names else 'aucun')
    check('langage ARM:LE:32:Cortex',
          dict(ordered).get('TI WiLink firmware (chunked)')
          == 'ARM:LE:32:Cortex')

    import pyghidra
    with pyghidra.open_program(path, project_location=PROJECT,
                               project_name='WLLoaderTest', analyze=False,
                               loader='wltools.wl.WL18xxLoader') as flat:
        program = flat.getCurrentProgram()
        blocks = blocks_of(program)
        chunks = [b for b in blocks if b[0].startswith('chunk')]
        check('15 blocs de chunk crees', len(chunks) == 15,
              '%d' % len(chunks))
        by_addr = {addr: size for _n, addr, size in chunks}
        check('chunk 0 a 0x0, taille 0x1d670', by_addr.get(0) == 0x1d670,
              hex(by_addr.get(0, 0)))
        check('chunk 1 a 0x100000, taille 0x20000',
              by_addr.get(0x100000) == 0x20000)
        check('chunk 14 a 0x80958000 (au-dela de 0x7fffffff)',
              0x80958000 in by_addr)

        st = program.getSymbolTable()
        reset = list(st.getSymbols('Reset_Handler'))
        check('Reset_Handler etiquete', len(reset) > 0,
              hex(reset[0].getAddress().getOffset()) if reset else 'absent')
        traces = [s for s in st.getAllSymbols(False)
                  if s.getName().startswith('trace_')]
        check('labels de trace poses', len(traces) > 400, '%d' % len(traces))
        check('commentaires de trace poses',
              program.getListing().getCommentAddressCount() > 900,
              '%d' % program.getListing().getCommentAddressCount())


def test_bts(path):
    # TODO y'a que TIInit_11.8.32 ici. Les 6.2/6.6/7.2 du corpus parsent bien
    # mais elles ont aucun poke 0xff03, donc cette partie est pas couverte.
    print('\n[2] script BT TIInit_*.bts')
    names = [n for n, _ in loaders_for(path)]
    check('le loader se declare',
          'TI Bluetooth init script (.bts patch)' in names, ', '.join(names[:3]))
    check('il passe devant Raw Binary',
          names and names[0] == 'TI Bluetooth init script (.bts patch)',
          names[0] if names else 'aucun')

    import pyghidra
    with pyghidra.open_program(path, project_location=PROJECT,
                               project_name='WLLoaderTest', analyze=False,
                               loader='wltools.wl.WlBtsLoader') as flat:
        program = flat.getCurrentProgram()
        blocks = blocks_of(program)
        patches = [b for b in blocks if b[0].startswith('patch_')]
        check('11 blobs de patch charges', len(patches) == 11,
              '%d' % len(patches))
        check('blob principal a 0x20000000',
              any(a == 0x20000000 for _n, a, _s in patches))
        pokes = [s for s in program.getSymbolTable().getAllSymbols(False)
                 if s.getName().startswith('bts_poke_')]
        check('32 pokes etiquetes', len(pokes) == 32, '%d' % len(pokes))


def test_rejection(blobs):
    print('\n[3] refus des fichiers hors format')
    ours = {'TI WiLink firmware (chunked)',
            'TI Bluetooth init script (.bts patch)'}
    cases = [(os.path.join(blobs, 'wl18xx-conf.bin'), 'wl18xx-conf.bin'),
             ('/bin/true', 'ELF complet')]
    for path, label in cases:
        if not os.path.exists(path):
            continue
        names = {n for n, _ in loaders_for(path)}
        check('%s refuse' % label, not (names & ours),
              ', '.join(names & ours) or 'aucun')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--blobs', default='/lib/firmware/ti-connectivity')
    args = ap.parse_args()

    import pyghidra
    pyghidra.start()

    fw = os.path.join(args.blobs, 'wl18xx-fw-4.bin')
    bts = os.path.join(args.blobs, 'TIInit_11.8.32.bts')

    if os.path.exists(fw):
        test_firmware(fw)
    else:
        print('\n[1] saute : %s absent' % fw)
    if os.path.exists(bts):
        test_bts(bts)
    else:
        print('\n[2] saute : %s absent' % bts)
    test_rejection(args.blobs)

    failed = [label for label, ok, _ in RESULTS if not ok]
    print('\n=== %d verifications, %d echec(s) ===' % (len(RESULTS), len(failed)))
    for label in failed:
        print('    ECHEC : %s' % label)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
