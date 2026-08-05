"""
Passe-plat des symboles Ghidra -> IDA.

Le run Ghidra ecrit noms/namespaces/commentaires dans un JSON, le script IDA
le rejoue tel quel. Comme ca les deux outils affichent la meme chose et le
cote IDA n'a quasi aucune logique a lui (tant mieux, l'API IDA est penible).

Le JSON ressemble a ca:
{
  "source": "ghidra_wl.py",
  "image_base": "0x0",
  "functions": {"0001bd8c": {"name": "<fonction>", "namespace": "<fichier_c>"}},
  "comments":  {"0001069e": "<fichier.c>:<ligne> <fonction>()  <format printf>"},
  "labels":    {"80815444": "mmio_80815444"}
}
Les cles sont en hexa sans 0x parce que JSON n'a pas d'entier 32 bits non
signe qui tienne la route.
"""

from __future__ import print_function

import json

DEFAULT_PREFIXES = ('FUN_', 'SUB_', 'sub_', 'nullsub_', 'UNDEFINED')


def is_default(name):
    if not name:
        return True
    return name.startswith(DEFAULT_PREFIXES)


# cote Ghidra
def export_from_ghidra(program, path, source='ghidra'):
    """Rend le nombre d'entrees ecrites. A appeler dans une transaction."""
    fm = program.getFunctionManager()
    listing = program.getListing()

    functions = collecte_fonctions(fm)
    comments = collecte_commentaires(program, listing)
    labels = collecte_labels(program)

    data = {
        'source': source,
        'image_base': '0x%x' % program.getImageBase().getOffset(),
        'functions': functions,
        'comments': comments,
        'labels': labels,
    }
    with open(path, 'w') as f:
        json.dump(data, f, indent=1, sort_keys=True)
    print('[export] %d fonctions, %d commentaires, %d labels -> %s'
          % (len(functions), len(comments), len(labels), path))
    return len(functions)


def collecte_fonctions(fm):
    functions = {}
    for func in fm.getFunctions(True):
        name = func.getName()
        if is_default(name):
            continue
        ns = func.getParentNamespace()
        namespace = ''
        if ns is not None and not ns.isGlobal():
            namespace = ns.getName()
        cle = '%x' % func.getEntryPoint().getOffset()
        functions[cle] = {'name': name, 'namespace': namespace}
    return functions


def collecte_commentaires(program, listing):
    comments = {}
    for kind in (0, 3):        # 0 = EOL, 3 = plate
        it = listing.getCommentAddressIterator(program.getMemory(), True)
        while it.hasNext():
            addr = it.next()
            text = listing.getComment(kind, addr)
            if not text:
                continue
            cle = '%x' % addr.getOffset()
            if cle not in comments:
                comments[cle] = text
    return comments


def collecte_labels(program):
    # que les miens, sinon on reexporte les FUN_ de Ghidra et IDA en a deja
    labels = {}
    for sym in program.getSymbolTable().getAllSymbols(False):
        name = sym.getName()
        if name.startswith('mmio_') or name.startswith('bts_poke_'):
            labels['%x' % sym.getAddress().getOffset()] = name
    return labels


# cote IDA
def apply_in_ida(path, compat):
    """
    Applique un export Ghidra dans IDA. `compat` c'est le module ida_compat,
    passe en parametre pour que ce fichier reste importable sans IDA
    (sinon je peux plus le tester en local).
    """
    with open(path, 'r') as f:
        data = json.load(f)

    named = applique_fonctions(data.get('functions', {}), compat)
    labelled = applique_labels(data.get('labels', {}), compat)
    commented, skipped = applique_commentaires(data.get('comments', {}), compat)

    total_c = len(data.get('comments', {}))
    print('[import] %d fonctions nommees, %d/%d commentaires, %d/%d labels'
          % (named, commented, total_c, labelled, len(data.get('labels', {}))))
    if skipped:
        print('         %d commentaires hors segment, ignores par IDA' % skipped)
    return named


def applique_fonctions(fonctions, compat):
    named = 0
    for addr_hex in fonctions:
        info = fonctions[addr_hex]
        ea = int(addr_hex, 16)
        current = compat.func_name(ea)
        if current and not is_default(current):
            continue    # deja nomme a la main, on ecrase pas
        name = info['name']
        ns = info.get('namespace')
        if ns:
            name = '%s__%s' % (ns, name)   # IDA n'a pas de namespaces
        if compat.set_func_name(ea, name):
            named += 1
    return named


def applique_labels(labels, compat):
    # les mmio_* et bts_poke_* tombent hors des blocs charges. Ghidra accepte
    # un symbole non mappe, IDA non. Sans le ensure_mapped j'en perdais 504
    # sur 509.
    poses = 0
    for addr_hex in labels:
        ea = int(addr_hex, 16)
        compat.ensure_mapped(ea)
        if compat.set_label(ea, labels[addr_hex]):
            poses += 1
    return poses


def applique_commentaires(commentaires, compat):
    poses = 0
    rates = 0
    for addr_hex in commentaires:
        if compat.set_comment(int(addr_hex, 16), commentaires[addr_hex]):
            poses += 1
        else:
            rates += 1
    return poses, rates
