#!/usr/bin/env python3
"""
Charge et symbolise un firmware WiFi TI WiLink dans Ghidra.

    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
    /opt/ghidra_venv/bin/python ghidra_wl.py wl18xx-fw-4.bin --project /tmp/ghidra_proj --name WL18xx

Passer par pyghidra et pas analyzeHeadless: analyzeHeadless lance pas de
script Python, il repond "not started with PyGhidra". J'ai perdu une soiree
la dessus.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import wl_fw
import symbols_io

# headless via pyghidra, ou Script Manager du GUI
IN_GHIDRA = 'currentProgram' in globals()
DEFAULT_FIRMWARE = '/lib/firmware/ti-connectivity/wl18xx-fw-4.bin'

# vecteurs Cortex-M dans l'ordre, apres le SP
CORTEX_VECTORS = [
    'Reset_Handler', 'NMI_Handler', 'HardFault_Handler', 'MemManage_Handler',
    'BusFault_Handler', 'UsageFault_Handler', 'Reserved_7', 'Reserved_8',
    'Reserved_9', 'Reserved_10', 'SVC_Handler', 'DebugMon_Handler',
    'Reserved_13', 'PendSV_Handler', 'SysTick_Handler',
]


def addr_of(program, value):
    # pas flat.toAddr(), il deborde au dela de 0x7fffffff et le chunk 14 est
    # a 0x80958000
    space = program.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress('%x' % value)

def clean_name(name):
    """Garde que ce que Ghidra accepte dans un identifiant."""
    out = []
    for ch in name:
        out.append(ch if (ch.isalnum() or ch in '_.') else '_')
    cleaned = ''.join(out)
    if cleaned and cleaned[0].isdigit():
        cleaned = 'f_' + cleaned
    return cleaned or 'sans_nom'


def run(flat, program, fw, analysis=True):
    """Le boulot. Commun au headless et au GUI."""
    from java.io import ByteArrayInputStream

    mem = program.getMemory()
    fm = program.getFunctionManager()
    monitor = flat.getMonitor()

    # le firmware est pas plat, on refait les blocs a la main
    code = set(c.index for c in fw.code_chunks())
    for block in list(mem.getBlocks()):
        mem.removeBlock(block, monitor)
    for chunk in fw.chunks:
        data = fw.data_of(chunk)
        start = addr_of(program, chunk.addr)
        name = 'chunk%02d_%08x' % (chunk.index, chunk.addr)
        block = mem.createInitializedBlock(
            name, start, ByteArrayInputStream(data),
            len(data), monitor, False)
        block.setRead(True)
        block.setWrite(True)
        # traces + cibles des vecteurs, cf code_chunks()
        block.setExecute(chunk.index in code)
    print('[1] %d blocs memoire crees' % len(fw.chunks))

    # la table de vecteurs est dans le chunk 0, a 0x0
    print('[2] vecteurs Cortex-M poses : %d'
          % load_vectors(flat, fw, program, fm))

    if analysis:
        run_analysis(program, monitor)
    print('[3] fonctions creees par scan de prologues : %d'
          % scan_prologues(flat, fw, program, fm, monitor))
    coverage(fw, program)

    symbolize(flat, fw, program, fm)

    group_by_source(fw, program, fm)
    targets = mmio_report(program, fm)
    map_mmio(flat, program, targets)
    trace_helpers(flat, fw, program, fm)
    propagate_modules(program, fm, flat.getMonitor())


def main_headless():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware')
    ap.add_argument('--project', default='/tmp/ghidra_proj')
    ap.add_argument('--name', default='WL18xx')
    ap.add_argument('--no-analysis', action='store_true')
    ap.add_argument('--export-symbols', metavar='JSON',
                    help='exporte noms/commentaires pour le script IDA')
    args = ap.parse_args()

    fw = wl_fw.Firmware(args.firmware)
    fw.report()
    print('')

    import pyghidra
    pyghidra.start()

    # BinaryLoader charge a plat, c'est run() qui refait la carte derriere
    with pyghidra.open_program(args.firmware,
                               project_location=args.project,
                               project_name=args.name,
                               analyze=False,
                               language='ARM:LE:32:Cortex',
                               loader='ghidra.app.util.opinion.BinaryLoader') as flat:
        program = flat.getCurrentProgram()
        tx = program.startTransaction('symbolisation WiLink')
        try:
            run(flat, program, fw, not args.no_analysis)
            if args.export_symbols:
                symbols_io.export_from_ghidra(program, args.export_symbols,
                                              'ghidra_wl.py')
        finally:
            program.endTransaction(tx, True)
        print('\n=== termine, projet dans %s/%s ===' % (args.project, args.name))


def main_gui():
    """Script Manager: faut que le binaire soit deja ouvert en ARM:LE:32:Cortex."""
    from ghidra.program.flatapi import FlatProgramAPI

    path = os.environ.get('WL_FIRMWARE')
    if not path:
        try:
            path = askFile('firmware wl18xx-fw-4.bin', 'Choisir').getAbsolutePath()
        except Exception:
            path = DEFAULT_FIRMWARE
    fw = wl_fw.Firmware(path)
    fw.report()
    print('')
    flat = FlatProgramAPI(currentProgram)
    run(flat, currentProgram, fw, True)
    print('=== fini ===')


def main():
    if IN_GHIDRA:
        main_gui()
    else:
        main_headless()


def load_vectors(flat, fw, program, fm):
    """Chunk 0 = le SP initial puis les vecteurs, adresses Thumb donc impaires."""
    chunk0 = fw.chunk_for(0)
    if chunk0 is None:
        return 0
    data = fw.data_of(chunk0)
    import struct
    from ghidra.program.model.symbol import SourceType

    posed = 0
    for i in range(1, 48):          # large, de toute facon on s'arrete avant
        off = i * 4
        if off + 4 > len(data):
            break
        value = struct.unpack_from('<I', data, off)[0]
        if value in (0, 0xffffffff) or not (value & 1):
            continue
        target = value & ~1
        if fw.chunk_for(target) is None:
            continue
        addr = addr_of(program, target)
        try:
            flat.disassemble(addr)
            func = fm.getFunctionAt(addr)
            if func is None:
                func = flat.createFunction(addr, None)
            name = (CORTEX_VECTORS[i - 1] if i - 1 < len(CORTEX_VECTORS)
                    else 'IRQ_%d_Handler' % (i - 16))
            if func is not None:
                func.setName(name, SourceType.USER_DEFINED)
                posed += 1
        except Exception:
            continue
    return posed


def run_analysis(program, monitor):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(monitor)


def scan_prologues(flat, fw, program, fm, monitor):
    """push {..., lr} = debut de fonction. Rattrape ce que l'analyse a loupe."""
    listing = program.getListing()
    created = 0
    for chunk in fw.code_chunks():
        data = fw.data_of(chunk)
        for off in range(0, len(data) - 1, 2):
            b0 = data[off]
            b1 = data[off + 1]
            # 0xb5 = push{..,lr} Thumb 16 bits, 0xe92d = le meme en 32 bits
            if not (b1 == 0xb5 or (b0 == 0x2d and b1 == 0xe9)):
                continue
            addr = addr_of(program, chunk.addr + off)
            if listing.getInstructionAt(addr) is not None:
                continue
            if fm.getFunctionContaining(addr) is not None:
                continue
            try:
                flat.disassemble(addr)
                if fm.getFunctionAt(addr) is None:
                    flat.createFunction(addr, None)
                if fm.getFunctionAt(addr) is not None:
                    created += 1
            except Exception:
                continue
    return created


def coverage(fw, program):
    # TODO il reste ~7% et ~15% des deux chunks non desassembles. Feuilles
    # sans prologue standard, ou donnees inline. Pas trouve mieux pour
    # l'instant.
    listing = program.getListing()
    fm = program.getFunctionManager()
    for chunk in fw.code_chunks():
        start = program.getAddressFactory().getDefaultAddressSpace().getAddress(chunk.addr)
        end = start.add(chunk.size - 1)
        covered = 0
        ins = listing.getInstructions(start, True)
        while ins.hasNext():
            i = ins.next()
            if i.getAddress() > end:
                break
            covered += i.getLength()
        nfunc = len([f for f in fm.getFunctions(True)
                     if start <= f.getEntryPoint() <= end])
        print('    chunk 0x%08x : %.1f%% de code, %d fonctions'
              % (chunk.addr, 100.0 * covered / chunk.size, nfunc))


def recover_function(flat, fw, program, fm, trace_addr, back=0x800):
    """Trace hors fonction: on remonte chercher un prologue, 2 Ko max."""
    chunk = fw.chunk_for(trace_addr)
    if chunk is None:
        return None
    data = fw.data_of(chunk)
    off = trace_addr - chunk.addr
    start = max(0, off - back)
    pos = off & ~1
    while pos >= start:
        if pos + 1 < len(data):
            b0 = data[pos]
            b1 = data[pos + 1]
            if b1 == 0xb5 or (b0 == 0x2d and b1 == 0xe9):
                addr = addr_of(program, chunk.addr + pos)
                try:
                    flat.disassemble(addr)
                    func = fm.getFunctionAt(addr)
                    if func is None:
                        func = flat.createFunction(addr, None)
                    if func is not None and func.getBody().contains(
                            addr_of(program, trace_addr)):
                        return func
                except Exception:
                    return None
                return None
        pos -= 2
    return None


def symbolize(flat, fw, program, fm):
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import (DuplicateNameException,
                                       InvalidInputException)
    listing = program.getListing()

    renamed = 0
    commented = 0
    orphan = 0
    recovered = 0
    already = {}
    conflicts = {}
    for trace in fw.traces:
        addr = addr_of(program, trace.addr)
        # le texte de log en commentaire, c'est ce qui sert le plus au final
        try:
            note = '%s:%d %s()  %s' % (trace.source, trace.line,
                                       trace.func, trace.fmt.strip())
            listing.setComment(addr, 0, note)   # 0 = EOL_COMMENT
            commented += 1
        except Exception:
            pass

        func = fm.getFunctionContaining(addr)
        if func is None:
            # rien ici, on remonte chercher un prologue
            func = recover_function(flat, fw, program, fm, trace.addr)
            if func is None:
                orphan += 1
                continue
            recovered += 1
        entry = func.getEntryPoint().getOffset()
        # plusieurs traces sur la meme fonction doivent donner le meme nom,
        # sinon c'est que Ghidra en a colle deux ensemble
        if entry in already:
            if already[entry] != trace.func:
                if entry not in conflicts:
                    conflicts[entry] = set()
                conflicts[entry].add(trace.func)
                conflicts[entry].add(already[entry])
            continue
        name = clean_name(trace.func)
        if not func.getName().startswith(('FUN_', 'SUB_')):
            already[entry] = trace.func
            continue
        try:
            func.setName(name, SourceType.USER_DEFINED)
            already[entry] = trace.func
            renamed += 1
        except (DuplicateNameException, InvalidInputException):
            pass

    # TODO 0x00002d62 porte des traces de 4 sources differentes. C'est une
    # machine a etats dispatchee par table et Ghidra l'a collee en un bloc.
    # Je signale, je decoupe pas, ca se fait a la main.
    dispo = set()
    for trace in fw.traces:
        dispo.add(trace.func)

    print('[4] fonctions renommees depuis les traces : %d' % renamed)
    print('    commentaires poses : %d' % commented)
    print('    fonctions recuperees par remontee de prologue : %d' % recovered)
    print('    traces toujours hors fonction : %d' % orphan)
    print('    noms distincts disponibles : %d' % len(dispo))
    if conflicts:
        print('    %d fonctions portent des traces de plusieurs sources'
              % len(conflicts))
        print('    (= bornes de fonction fausses, a decouper a la main) :')
        for entry in sorted(conflicts)[:5]:
            noms = sorted(conflicts[entry])
            print('       0x%08x : %s' % (entry, ', '.join(noms)))




def group_by_source(fw, program, fm):
    """Un namespace par fichier source, ca rend le Symbol Tree navigable."""
    from ghidra.program.model.symbol import SourceType

    st = program.getSymbolTable()
    glob = program.getGlobalNamespace()
    cache = {}
    placed = 0
    for trace in fw.traces:
        addr = addr_of(program, trace.addr)
        func = fm.getFunctionContaining(addr)
        if func is None or func.getName().startswith(('FUN_', 'SUB_')):
            continue
        src = trace.source.replace('.', '_')
        ns = cache.get(src)
        if ns is None:
            try:
                ns = st.getOrCreateNameSpace(glob, src, SourceType.USER_DEFINED)
                cache[src] = ns
            except Exception:
                continue
        try:
            if func.getParentNamespace() != ns:
                func.setParentNamespace(ns)
                placed += 1
        except Exception:
            pass
    print('[5] fonctions rangees par fichier source : %d (%d modules)'
          % (placed, len(cache)))


# Au dessus de ca c'est un deplacement negatif, pas un registre:
# ldr r0,[r3,#-0x28] avec une base nulle ressort en 0xffffffd8. Ca me faisait
# 146 faux positifs sur 509 au depart.
ARTIFACT_FLOOR = 0xffff0000


def mmio_report(program, fm, top=15):
    """
    Les adresses referencees hors des chunks charges = candidats registres.

    On peut pas les nommer, TI publie pas la carte memoire. Par contre on
    peut dire lesquels sont touches et depuis ou, et ca aide deja pas mal.
    """
    mem = program.getMemory()
    listing = program.getListing()
    targets = {}
    artifacts = {}
    mapped = 0
    ins = listing.getInstructions(True)
    while ins.hasNext():
        instr = ins.next()
        for ref in instr.getReferencesFrom():
            dest = ref.getToAddress()
            if dest is None:
                continue
            off = dest.getOffset() & 0xffffffff

            # getBlock teste dans l'espace de la ref, alors que map_mmio
            # reconstruit dans l'espace par defaut. A melanger les deux je me
            # retrouvais avec des mmio_ poses sur la table de vecteurs. Donc
            # on normalise d'abord.
            if mem.getBlock(dest) is not None:
                continue
            if mem.getBlock(addr_of(program, off)) is not None:
                mapped += 1
                continue

            if off >= ARTIFACT_FLOOR:
                bucket = artifacts
            else:
                bucket = targets
            if off not in bucket:
                bucket[off] = set()
            func = fm.getFunctionContaining(instr.getAddress())
            if func is not None:
                bucket[off].add(func.getName())

    if mapped:
        print('[6] %d references ecartees : elles retombent dans un bloc deja '
              'charge une fois ramenees dans l espace par defaut' % mapped)

    if artifacts:
        print('[6] %d adresses >= 0x%08x ecartees : deplacements negatifs '
              'resolus sur une base nulle, pas des registres'
              % (len(artifacts), ARTIFACT_FLOOR))
    print('[6] adresses hors image (registres materiels) : %d' % len(targets))

    # regroupement par region de 1 Mo, ca donne une idee de la carte
    regions = {}
    for off in targets:
        base = off & 0xfff00000
        regions[base] = regions.get(base, 0) + 1

    par_region = []
    for base in regions:
        par_region.append((regions[base], base))
    par_region.sort(reverse=True)
    for n, base in par_region[:8]:
        print('    region 0x%08x : %d adresses' % (base, n))

    par_addr = []
    for off in targets:
        par_addr.append((len(targets[off]), off))
    par_addr.sort(reverse=True)
    for n, off in par_addr[:top]:
        exemples = sorted(targets[off])[:3]
        print('    0x%08x  touche par %d fonction(s) : %s'
              % (off, n, ', '.join(exemples)))

    return targets


def map_mmio(flat, program, targets, page=0x1000):
    """
    Materialise les zones de registres en blocs non initialises.

    Sans ca les references restent dans le vide: aucune xref, et le
    decompilateur sort des constantes nues.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import InvalidInputException

    mem = program.getMemory()
    st = program.getSymbolTable()
    listing = program.getListing()
    monitor = flat.getMonitor()

    pages = sorted(set(off & ~(page - 1) for off in targets))
    created = 0
    for base in pages:
        start = addr_of(program, base)
        if mem.getBlock(start) is not None:
            continue
        try:
            block = mem.createUninitializedBlock(
                'mmio_%08x' % base, start, page, False)
            block.setRead(True)
            block.setWrite(True)
            block.setVolatile(True)   # des registres, faut pas cacher la valeur
            created += 1
        except Exception:
            continue

    labelled = 0
    for off, funcs in targets.items():
        addr = addr_of(program, off)
        if mem.getBlock(addr) is None:
            continue
        try:
            st.createLabel(addr, 'mmio_%08x' % off, SourceType.USER_DEFINED)
            listing.setComment(addr, 3, 'registre materiel, %d fonction(s) : %s'
                               % (len(funcs), ', '.join(sorted(funcs)[:6])))
            labelled += 1
        except InvalidInputException:
            continue

    print('[7] blocs MMIO crees : %d (pages de 0x%x), adresses etiquetees : %d'
          % (created, page, labelled))




def _call_target(listing, addr, window=3):
    """
    Cherche le callee autour d'un site de trace.

    Selon le compilo l'adresse tombe sur le bl, sur l'adresse de retour, ou
    deux ou trois instructions plus loin. D'ou la fenetre.

    Rend (adresse, etat), etat parmi direct / indirect / pas_de_code /
    pas_d_appel.
    """
    instr = listing.getInstructionAt(addr)
    if instr is None:
        instr = listing.getInstructionBefore(addr)
    if instr is None:
        return None, 'pas_de_code'

    seen_call = False
    cursor = instr
    for _ in range(window):
        if cursor is None:
            break
        try:
            if cursor.getFlowType().isCall():
                seen_call = True
                flows = cursor.getFlows()
                if flows:
                    return flows[0], 'direct'
        except Exception:
            pass
        cursor = cursor.getNext()

    # meme chose en arriere. Oui c'est copie colle, j'ai essaye de le
    # factoriser avec un pas +1/-1 et c'etait moins lisible.
    cursor = instr.getPrevious()
    for _ in range(window):
        if cursor is None:
            break
        try:
            if cursor.getFlowType().isCall():
                seen_call = True
                flows = cursor.getFlows()
                if flows:
                    return flows[0], 'direct'
        except Exception:
            pass
        cursor = cursor.getPrevious()

    return None, 'indirect' if seen_call else 'pas_d_appel'


def trace_helpers(flat, fw, program, fm):
    """
    Nomme les helpers de trace, un par arite (nargs va de 0 a 4).

    Identification par vote sur les callees. C'est une heuristique et le vote
    sort qu'a 15-25%, donc bof. Ce qui me fait y croire quand meme c'est que
    Trace0..3 tombent a des adresses consecutives, donc une table de thunks.

    TODO verifier a la main avant de s'appuyer sur les prototypes.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import (DuplicateNameException,
                                       InvalidInputException)

    listing = program.getListing()
    votes = {}
    stats = {}
    for trace in fw.traces:
        target, state = _call_target(listing, addr_of(program, trace.addr))
        stats[state] = stats.get(state, 0) + 1
        if target is None:
            continue
        if trace.nargs not in votes:
            votes[trace.nargs] = {}
        cible = target.getOffset()
        votes[trace.nargs][cible] = votes[trace.nargs].get(cible, 0) + 1

    resume = []
    for etat in sorted(stats):
        resume.append('%s=%d' % (etat, stats[etat]))
    print('[8] sites de trace : %s' % ', '.join(resume))

    named = 0
    for nargs in sorted(votes):
        # le gagnant du vote
        classement = []
        total = 0
        for a in votes[nargs]:
            classement.append((votes[nargs][a], a))
            total += votes[nargs][a]
        classement.sort(reverse=True)
        count = classement[0][0]
        best = classement[0][1]

        func = fm.getFunctionAt(addr_of(program, best))
        if func is None:
            func = fm.getFunctionContaining(addr_of(program, best))
        if func is None:
            continue

        name = 'Trace%d' % nargs
        try:
            func.setName(name, SourceType.USER_DEFINED)
        except (DuplicateNameException, InvalidInputException):
            pass
        poser_prototype(program, func, name, nargs)

        named += 1
        print('    %-8s @ %s  %d/%d des traces a %d arg(s)'
              % (name, func.getEntryPoint(), count, total, nargs))
    print('[8] helpers de trace nommes et types : %d' % named)


def poser_prototype(program, func, name, nargs):
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.data import (FunctionDefinitionDataType,
                                           ParameterDefinitionImpl,
                                           UnsignedIntegerDataType,
                                           VoidDataType)
    from ghidra.program.model.symbol import SourceType

    sig = FunctionDefinitionDataType(name)
    sig.setReturnType(VoidDataType.dataType)
    params = [ParameterDefinitionImpl(
        'trace_id', UnsignedIntegerDataType.dataType, None)]
    for i in range(nargs):
        params.append(ParameterDefinitionImpl(
            'a%d' % (i + 1), UnsignedIntegerDataType.dataType, None))
    sig.setArguments(params)
    try:
        ApplyFunctionSignatureCmd(func.getEntryPoint(), sig,
                                  SourceType.USER_DEFINED).applyTo(program)
    except Exception:
        pass




def propagate_modules(program, fm, monitor, passes=3, seuil=0.8):
    """
    Range les fonctions anonymes dans le module d'ou elles sont appelees.

    Si >=80% des appelants viennent du meme namespace, la fonction y va et
    prend le prefixe qui va avec.

    A LIRE avant de se fier au resultat: le prefixe dit "appelee depuis", pas
    "definie dans". Une fonction utilitaire partagee finit rattachee a celui
    qui l'appelle le plus, ce qui est faux mais pratique.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import (DuplicateNameException,
                                       InvalidInputException)

    total = 0
    for _pass in range(passes):
        placed = 0
        for func in list(fm.getFunctions(True)):
            if not func.getName().startswith(('FUN_', 'SUB_')):
                continue
            callers = func.getCallingFunctions(monitor)
            if not callers:
                continue
            counts = {}
            for caller in callers:
                ns = caller.getParentNamespace()
                if ns is None or ns.isGlobal():
                    continue
                counts[ns] = counts.get(ns, 0) + 1
            if not counts:
                continue
            best_ns = None
            best = 0
            nb = 0
            for ns in counts:
                nb += counts[ns]
                if counts[ns] > best:
                    best = counts[ns]
                    best_ns = ns
            if best < seuil * nb:
                continue
            try:
                func.setParentNamespace(best_ns)
                func.setName('%s_sub_%s' % (best_ns.getName(),
                                            func.getEntryPoint()),
                             SourceType.ANALYSIS)
                placed += 1
            except (DuplicateNameException, InvalidInputException):
                continue
        total += placed
        if placed == 0:
            break       # plus rien a gagner, les passes suivantes font rien
    print('[9] fonctions anonymes rattachees a un module : %d' % total)


if __name__ == '__main__':
    main()
