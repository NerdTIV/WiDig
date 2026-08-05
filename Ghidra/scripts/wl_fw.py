"""
Parsing du firmware WiLink et du .bts Bluetooth.

Rien de Ghidra ni d'IDA la-dedans, c'est fait expres: les deux frontends
importent ce fichier, et je peux le lancer tout seul en ligne de commande
quand je veux comprendre un blob.

Le format du fw c'est celui que lit wlcore/boot.c dans le noyau:

    u32 be   nombre de chunks
    par chunk:
        u32 be   adresse de chargement
        u32 be   taille
        <taille octets>

Colle derriere le dernier chunk il y a la base de traces:

    "GTRACEBINMAGICHDR" puis des enregistrements
    "<addr>,<ligne>,<fichier.c>,<fonction>,<nargs>|<format printf>"

addr = site d'appel de la trace, bit Thumb a 1. C'est ma table de symboles.

ATTENTION si tu touches a ce fichier: on lit un binaire qu'on ne controle
pas. Les bornes plus bas c'est pas de la deco, je me suis fait avoir avec un
wl18xx-fw-4.bin tronque a la moitie.
"""

from __future__ import print_function

import re
import struct

TRACE_MAGIC = b'GTRACEBINMAGICHDR'
BTS_MAGIC = b'BTSB'

# Bornes anti fichier pourri. Large: le plus gros que j'aie vu fait 15 chunks
# et 963 traces.
MAX_CHUNKS = 256        # TODO jamais vu au dela de 15, valeur au pif
MAX_TRACES = 100000
MAX_TRACE_DB = 8 * 1024 * 1024

# Sans base de traces il en faut au moins ca (les vrais en ont 6 ou 15)
MIN_CHUNKS_SANS_TRACES = 2

# "nombre,nombre,fichier,fonction,nombre|"
# les \d sont bornes: 100000 chiffres d'affilee font ramer int() et finissent
# par lever en 3.11+
REC_RE = re.compile(r'(\d{1,10}),(\d{1,7}),([^,\r\n]{1,120}),([^,\r\n]{1,120}),(\d{1,2})\|')

BTS_ACTIONS = {
    1: 'send_command',
    2: 'wait_event',
    3: 'serial_port_params',
    4: 'delay',
    5: 'run_script',
    6: 'remarks',
}


class Chunk(object):
    def __init__(self, index, addr, size, file_offset):
        self.index = index
        self.addr = addr
        self.size = size
        self.file_offset = file_offset

    def contains(self, addr):
        return self.addr <= addr < self.addr + self.size

    def __repr__(self):
        return 'Chunk(%d, addr=0x%08x, size=0x%x)' % (
            self.index, self.addr, self.size)


class Trace(object):
    def __init__(self, addr, line, source, func, nargs, fmt):
        self.addr = addr        # site d'appel, bit Thumb deja vire
        self.thumb = bool(addr & 1)
        self.line = line
        self.source = source
        self.func = func
        self.nargs = nargs
        self.fmt = fmt

    def __repr__(self):
        return 'Trace(0x%08x, %s:%d, %s)' % (
            self.addr, self.source, self.line, self.func)


class Firmware(object):
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.raw = f.read()
        self.path = path
        self.chunks = []
        self.traces = []
        self._parse_chunks()
        self._parse_traces()

    def _parse_chunks(self):
        self.trace_offset = 0
        if len(self.raw) < 12:
            return          # meme pas la place d'un chunk

        count = struct.unpack_from('>I', self.raw, 0)[0]
        if count == 0 or count > MAX_CHUNKS:
            return

        off = 4
        for i in range(count):
            if off + 8 > len(self.raw):
                self.chunks = []
                return
            addr, size = struct.unpack_from('>II', self.raw, off)
            off += 8
            if off + size > len(self.raw):
                self.chunks = []
                return
            self.chunks.append(Chunk(i, addr, size, off))
            off += size
        self.trace_offset = off

    def data_of(self, chunk):
        return self.raw[chunk.file_offset:chunk.file_offset + chunk.size]

    def has_trace_db(self):
        tail = self.raw[self.trace_offset:self.trace_offset + len(TRACE_MAGIC)]
        return tail == TRACE_MAGIC

    def _parse_traces(self):
        if not self.chunks or not self.has_trace_db():
            return

        debut = self.trace_offset + len(TRACE_MAGIC)
        tail = self.raw[debut:debut + MAX_TRACE_DB]
        texte = tail.decode('latin1')

        # Surtout pas de split('\n') ici: le format printf contient lui meme
        # des \r\n, j'ai perdu 200 traces avant de comprendre. Je repere les
        # debuts, et le format va jusqu'au debut du suivant.
        recs = []
        for m in REC_RE.finditer(texte):
            recs.append(m)
            if len(recs) >= MAX_TRACES:
                break

        i = 0
        while i < len(recs):
            m = recs[i]
            if i + 1 < len(recs):
                fin = recs[i + 1].start()
            else:
                fin = len(texte)
            fmt = texte[m.end():fin].rstrip('\r\n')
            i += 1
            try:
                addr = int(m.group(1))
                line = int(m.group(2))
                nargs = int(m.group(5))
            except ValueError:
                #print('rec bancal:', repr(m.group(0)))
                continue    # y'en a un millier des bancals, on saute
            self.traces.append(Trace(
                addr=addr & ~1,
                line=line,
                source=m.group(3),
                func=m.group(4),
                nargs=nargs,
                fmt=fmt,
            ))

    def chunk_for(self, addr):
        for c in self.chunks:
            if c.contains(addr):
                return c
        return None

    def vector_chunks(self):
        """Les chunks vises par la table de vecteurs Cortex-M du chunk 0."""
        chunk0 = self.chunk_for(0)
        if chunk0 is None:
            return set()
        data = self.data_of(chunk0)
        out = set()
        for i in range(1, 48):
            off = i * 4
            if off + 4 > len(data):
                break
            val = struct.unpack_from('<I', data, off)[0]
            # un vecteur valide est impair, c'est le bit Thumb
            if val in (0, 0xffffffff) or not (val & 1):
                continue
            c = self.chunk_for(val & ~1)
            if c is not None:
                out.add(c.index)
        return out

    def code_chunks(self):
        """
        Les chunks qui portent du code: ceux qui ont des traces + ceux vises
        par les vecteurs.

        Les traces toutes seules ca suffit pas: wl18xx-fw.bin et les vieux
        wl127x n'en ont aucune, sans les vecteurs on marquerait tout le
        firmware en donnees.
        """
        idx = self.vector_chunks()
        for t in self.traces:
            c = self.chunk_for(t.addr)
            if c is not None:
                idx.add(c.index)

        out = []
        for c in self.chunks:
            if c.index in idx:
                out.append(c)
        return out

    def symbols(self):
        # on a les sites d'appel, pas les prologues. C'est au frontend de
        # remonter jusqu'au debut de la fonction.
        out = []
        for t in self.traces:
            out.append((t.addr, t.func, t.source, t.line))
        return out

    def report(self):
        print('firmware  : %s (%d octets)' % (self.path, len(self.raw)))
        print('chunks    : %d' % len(self.chunks))
        for c in self.chunks:
            n = 0
            for t in self.traces:
                if c.contains(t.addr):
                    n += 1
            marque = ''
            if n:
                marque = '   <- %d traces (code)' % n
            print('   %2d  addr=0x%08x  size=0x%-8x%s'
                  % (c.index, c.addr, c.size, marque))
        print('traces    : %d' % len(self.traces))
        fonctions = set()
        sources = set()
        for t in self.traces:
            fonctions.add(t.func)
            sources.add(t.source)
        print('fonctions : %d' % len(fonctions))
        print('sources   : %d' % len(sources))
        # les traces hors chunk sont des vraies, elles pointent dans une zone
        # RAM qui n'est pas dans le fichier
        perdues = 0
        for t in self.traces:
            if self.chunk_for(t.addr) is None:
                perdues += 1
        if perdues:
            print('traces hors chunk : %d' % perdues)


def looks_like_firmware(data):
    """
    Est ce que c'est un conteneur WiLink? rend (oui/non, chunks, a_des_traces).

    Deux facons d'en etre sur:
      - la base de traces est la, ca s'invente pas;
      - sinon les chunks doivent consommer EXACTEMENT tout le fichier.

    La 2eme regle a l'air arbitraire mais je l'ai mesuree: sur les 16 fw
    WiLink de linux-firmware, ceux sans traces tombent tous a 100% pile. Ma
    premiere version disait juste "au moins un chunk" et revendiquait 865
    binaires sur 1200 dans /bin et /usr/lib. Pas terrible.
    """
    sonde = Firmware.__new__(Firmware)
    sonde.raw = data
    sonde.path = '<memoire>'
    sonde.chunks = []
    sonde.traces = []
    sonde._parse_chunks()

    if not sonde.chunks:
        return False, [], False
    if sonde.has_trace_db():
        return True, sonde.chunks, True

    pile_poil = sonde.trace_offset == len(data)
    assez = len(sonde.chunks) >= MIN_CHUNKS_SANS_TRACES
    return (pile_poil and assez), sonde.chunks, False


# TIInit_*.bts

class BtsAction(object):
    def __init__(self, index, atype, payload, offset):
        self.index = index
        self.type = atype
        self.name = BTS_ACTIONS.get(atype, 'inconnu_%d' % atype)
        self.payload = payload
        self.offset = offset

    def hci(self):
        """Pour un send_command: (opcode, plen, params). Sinon None."""
        if self.type != 1 or len(self.payload) < 4:
            return None
        if self.payload[0] != 0x01:     # paquet HCI command
            return None
        opcode = struct.unpack_from('<H', self.payload, 1)[0]
        plen = self.payload[3]
        return opcode, plen, self.payload[4:4 + plen]

    def __repr__(self):
        return 'BtsAction(%d, %s, %d octets)' % (
            self.index, self.name, len(self.payload))


class BtsScript(object):
    HEADER_SIZE = 32        # magic + version + 24 octets reserves
    MAX_ACTIONS = 20000

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.raw = f.read()
        self.path = path
        self.actions = []
        self._parse()

    def _parse(self):
        if not self.raw.startswith(BTS_MAGIC):
            raise ValueError('magic BTSB absent')
        off = self.HEADER_SIZE
        i = 0
        while off + 4 <= len(self.raw) and i < self.MAX_ACTIONS:
            atype, size = struct.unpack_from('<HH', self.raw, off)
            debut = off + 4
            if debut + size > len(self.raw):
                break
            self.actions.append(
                BtsAction(i, atype, self.raw[debut:debut + size], debut))
            off = debut + size
            i += 1

    def _payloads(self, opcode_voulu):
        """Les (addr, data) portes par un opcode vendor donne."""
        out = []
        for a in self.actions:
            pkt = a.hci()
            if pkt is None:
                continue
            opcode, _plen, params = pkt
            if opcode != opcode_voulu or len(params) < 5:
                continue
            addr = struct.unpack_from('<I', params, 0)[0]
            n = params[4]
            if not isinstance(n, int):
                n = ord(n)      # py2, je sais pas si ca sert encore
            out.append((addr, params[5:5 + n]))
        return out

    def patch_blobs(self):
        """
        0xff05 = HCI_VS_Write_Memory_Block chez TI. addr u32 le | len u8 |
        data.

        Les morceaux se suivent en adresses contigues (240 octets a chaque
        fois), je les recolle.
        """
        morceaux = self._payloads(0xff05)
        morceaux.sort()     # tri sur l'adresse, c'est le 1er champ du tuple
        blobs = []
        for addr, data in morceaux:
            if blobs and addr == blobs[-1][0] + len(blobs[-1][1]):
                blobs[-1] = (blobs[-1][0], blobs[-1][1] + data)
            else:
                blobs.append((addr, data))
        return blobs

    def pokes(self):
        """0xff03 = ecriture memoire ponctuelle."""
        return self._payloads(0xff03)

    def report(self):
        print('script BT : %s (%d octets)' % (self.path, len(self.raw)))
        print('actions   : %d' % len(self.actions))
        compteur = {}
        for a in self.actions:
            compteur[a.name] = compteur.get(a.name, 0) + 1
        for nom in sorted(compteur):
            print('   %-20s %d' % (nom, compteur[nom]))

        self._report_opcodes()

        blobs = self.patch_blobs()
        total = 0
        for _addr, data in blobs:
            total += len(data)
        print('patch de code (0xff05) : %d blob(s), %d octets au total'
              % (len(blobs), total))
        for addr, data in blobs:
            print('   0x%08x - 0x%08x  (%d octets)'
                  % (addr, addr + len(data), len(data)))

        pokes = self.pokes()
        print('ecritures memoire (0xff03) : %d' % len(pokes))
        if pokes:
            lo = pokes[0][0]
            hi = pokes[0][0]
            for addr, _val in pokes:
                if addr < lo:
                    lo = addr
                if addr > hi:
                    hi = addr
            print('   plage adressee : 0x%08x - 0x%08x' % (lo, hi))

    def _report_opcodes(self):
        opcodes = {}
        total_params = 0
        for a in self.actions:
            pkt = a.hci()
            if pkt is None:
                continue
            opcode, plen, _params = pkt
            opcodes[opcode] = opcodes.get(opcode, 0) + 1
            total_params += plen

        print('opcodes HCI distincts : %d, %d octets de parametres'
              % (len(opcodes), total_params))
        top = []
        for op in opcodes:
            top.append((opcodes[op], op))
        top.sort(reverse=True)
        for n, op in top[:10]:
            # ogf/ocf: cf Bluetooth core spec, vol 4 partie E 5.4.1
            print('   opcode 0x%04x (ogf=0x%02x ocf=0x%03x) x%d'
                  % (op, op >> 10, op & 0x3ff, n))


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('usage: wl_fw.py <firmware.bin> [TIInit.bts]')
        sys.exit(1)

    fw = Firmware(sys.argv[1])
    if not fw.chunks:
        print('%s : pas un conteneur WiLink' % sys.argv[1])
        sys.exit(1)
    fw.report()

    if len(sys.argv) > 2:
        print('')
        BtsScript(sys.argv[2]).report()
