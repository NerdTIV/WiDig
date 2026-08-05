/* Parsing du firmware WiLink et du script d'init BT.
 *
 * Volontairement aucun import ghidra.* ici: le jumeau Python
 * (scripts/wl_fw.py) fait exactement la meme chose et je veux pouvoir
 * comparer les deux quand un blob passe d'un cote et pas de l'autre.
 *
 * Le fichier vient de l'utilisateur, pas de nous. Les bornes plus bas sont
 * pas decoratives.
 */
package wltools.wl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class WlFirmware {

	public static final byte[] TRACE_MAGIC =
		"GTRACEBINMAGICHDR".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

	public static final byte[] BTS_MAGIC = { 'B', 'T', 'S', 'B' };

	private static final int MAX_CHUNKS = 256;
	private static final int MAX_TRACES = 100000;
	private static final int MAX_TRACE_DB = 8 * 1024 * 1024;

	/** Sans base de traces, il faut au moins ce nombre de chunks. */
	public static final int MIN_CHUNKS_SANS_TRACES = 2;

	// les \d sont bornes, sinon un fichier avec 100000 chiffres d'affilee
	// fait ramer le parseur pour rien
	private static final Pattern REC = Pattern.compile(
		"(\\d{1,10}),(\\d{1,7}),([^,\\r\\n]{1,120}),([^,\\r\\n]{1,120}),(\\d{1,2})\\|");

	public static final class Chunk {
		public final int index;
		public final long addr;
		public final long size;
		public final long fileOffset;

		Chunk(int index, long addr, long size, long fileOffset) {
			this.index = index;
			this.addr = addr;
			this.size = size;
			this.fileOffset = fileOffset;
		}

		public boolean contains(long a) {
			return a >= addr && a < addr + size;
		}

		public String blockName() {
			return String.format("chunk%02d_%08x", index, addr);
		}
	}

	public static final class Trace {
		public final long addr;      // site d'appel, bit Thumb enleve
		public final int line;
		public final String source;
		public final String func;
		public final int nargs;
		public final String fmt;

		Trace(long addr, int line, String source, String func, int nargs, String fmt) {
			this.addr = addr;
			this.line = line;
			this.source = source;
			this.func = func;
			this.nargs = nargs;
			this.fmt = fmt;
		}
	}

	private WlFirmware() {
	}

	private static long u32be(byte[] b, int off) {
		return ((long) (b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
			| ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
	}

	private static long u32le(byte[] b, int off) {
		return ((long) (b[off + 3] & 0xff) << 24) | ((b[off + 2] & 0xff) << 16)
			| ((b[off + 1] & 0xff) << 8) | (b[off] & 0xff);
	}

	/**
	 * Decoupe la liste de chunks. Liste vide si le fichier colle pas, et
	 * c'est ce qui sert de test d'acceptation aux deux loaders.
	 */
	public static List<Chunk> parseChunks(byte[] data) {
		List<Chunk> chunks = new ArrayList<>();
		if (data.length < 12) {
			return chunks;
		}
		long count = u32be(data, 0);
		if (count == 0 || count > MAX_CHUNKS) {
			return chunks;
		}
		int off = 4;
		for (int i = 0; i < count; i++) {
			if (off + 8 > data.length) {
				return new ArrayList<>();
			}
			long addr = u32be(data, off);
			long size = u32be(data, off + 4);
			off += 8;
			// size vient du fichier, donc on compare en long AVANT de s'en
			// servir comme index: un size proche de 2^32 passe en negatif
			// une fois caste et le test saute.
			if (size <= 0 || off + size > data.length) {
				return new ArrayList<>();
			}
			chunks.add(new Chunk(i, addr, size, off));
			off += (int) size;
		}
		return chunks;
	}

	/** Fin du dernier chunk = debut de la base de traces. */
	public static long traceOffset(List<Chunk> chunks) {
		if (chunks.isEmpty()) {
			return -1;
		}
		Chunk last = chunks.get(chunks.size() - 1);
		return last.fileOffset + last.size;
	}

	public static boolean hasTraceDb(byte[] data, List<Chunk> chunks) {
		long off = traceOffset(chunks);
		if (off < 0 || off + TRACE_MAGIC.length > data.length) {
			return false;
		}
		int base = (int) off;
		for (int i = 0; i < TRACE_MAGIC.length; i++) {
			if (data[base + i] != TRACE_MAGIC[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Est ce que c'est un conteneur WiLink?
	 *
	 * Soit la base de traces est la, soit les chunks consomment exactement
	 * tout le fichier. La 2eme regle vient d'une mesure: sur les 16 firmwares
	 * WiLink de linux-firmware ceux sans traces tombent a 100% pile, et une
	 * regle plus laxiste revendiquait 865 binaires sur 1200 dans /bin et
	 * /usr/lib.
	 */
	public static boolean looksLikeFirmware(byte[] data, List<Chunk> chunks) {
		if (chunks.isEmpty()) {
			return false;
		}
		if (hasTraceDb(data, chunks)) {
			return true;
		}
		return traceOffset(chunks) == data.length
			&& chunks.size() >= MIN_CHUNKS_SANS_TRACES;
	}

	/** Les chunks vises par la table de vecteurs Cortex-M du chunk 0. */
	public static Set<Integer> vectorChunks(byte[] data, List<Chunk> chunks) {
		Set<Integer> vus = new HashSet<>();
		Chunk chunk0 = null;
		for (Chunk c : chunks) {
			if (c.contains(0)) {
				chunk0 = c;
				break;
			}
		}
		if (chunk0 == null) {
			return vus;
		}
		for (int i = 1; i < 48; i++) {
			long off = chunk0.fileOffset + i * 4L;
			if (off + 4 > data.length || i * 4L + 4 > chunk0.size) {
				break;
			}
			long val = u32le(data, (int) off);
			// un vecteur valide est impair, c'est le bit Thumb
			if (val == 0 || val == 0xffffffffL || (val & 1) == 0) {
				continue;
			}
			long cible = val & ~1L;
			for (Chunk c : chunks) {
				if (c.contains(cible)) {
					vus.add(c.index);
					break;
				}
			}
		}
		return vus;
	}

	/**
	 * Les chunks qui portent du code: ceux avec des traces + ceux vises par
	 * les vecteurs. Sans les vecteurs, un firmware sans traces se retrouve
	 * entierement marque en donnees.
	 */
	public static Set<Integer> codeChunks(byte[] data, List<Chunk> chunks,
			List<Trace> traces) {
		Set<Integer> code = new HashSet<>(vectorChunks(data, chunks));
		for (Trace t : traces) {
			for (Chunk c : chunks) {
				if (c.contains(t.addr)) {
					code.add(c.index);
					break;
				}
			}
		}
		return code;
	}

	/**
	 * La base de traces, quand il y en a une. C'est notre table de symboles:
	 * chaque enregistrement donne le fichier source et le nom de fonction du
	 * site d'appel.
	 */
	public static List<Trace> parseTraces(byte[] data, List<Chunk> chunks) {
		List<Trace> traces = new ArrayList<>();
		if (!hasTraceDb(data, chunks)) {
			return traces;
		}
		int debut = (int) traceOffset(chunks) + TRACE_MAGIC.length;
		int longueur = Math.min(data.length - debut, MAX_TRACE_DB);
		String texte = new String(data, debut, longueur,
			java.nio.charset.StandardCharsets.ISO_8859_1);

		// surtout pas de split sur les lignes: le format printf contient lui
		// meme des \r\n. On repere les debuts d'enregistrement et le format
		// va jusqu'au debut du suivant.
		List<int[]> spans = new ArrayList<>();
		List<String[]> champs = new ArrayList<>();
		Matcher m = REC.matcher(texte);
		while (m.find() && spans.size() < MAX_TRACES) {
			spans.add(new int[] { m.start(), m.end() });
			champs.add(new String[] { m.group(1), m.group(2), m.group(3),
				m.group(4), m.group(5) });
		}

		for (int i = 0; i < spans.size(); i++) {
			int fin = (i + 1 < spans.size()) ? spans.get(i + 1)[0] : texte.length();
			String fmt = texte.substring(spans.get(i)[1], fin);
			while (fmt.endsWith("\r") || fmt.endsWith("\n")) {
				fmt = fmt.substring(0, fmt.length() - 1);
			}
			String[] f = champs.get(i);
			try {
				long brut = Long.parseLong(f[0]);
				traces.add(new Trace(brut & ~1L, Integer.parseInt(f[1]), f[2],
					f[3], Integer.parseInt(f[4]), fmt));
			}
			catch (NumberFormatException e) {
				// enregistrement bancal, on le saute. Y'en a un paquet.
			}
		}
		return traces;
	}

	// TIInit_*.bts

	public static final class BtsBlob {
		public final long addr;
		public final byte[] data;

		BtsBlob(long addr, byte[] data) {
			this.addr = addr;
			this.data = data;
		}
	}

	private static final int BTS_HEADER_SIZE = 32;
	private static final int MAX_BTS_ACTIONS = 20000;

	public static boolean isBts(byte[] data) {
		if (data.length < BTS_HEADER_SIZE + 4) {
			return false;
		}
		for (int i = 0; i < BTS_MAGIC.length; i++) {
			if (data[i] != BTS_MAGIC[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Les (addr, data) portes par un opcode vendor donne.
	 *
	 * Un send_command contient un paquet HCI: 0x01, opcode u16 le, plen u8,
	 * params. Et dans les params: addr u32 le | len u8 | data.
	 */
	private static List<BtsBlob> payloads(byte[] data, int opcodeVoulu) {
		List<BtsBlob> out = new ArrayList<>();
		if (!isBts(data)) {
			return out;
		}
		int off = BTS_HEADER_SIZE;
		int n = 0;
		while (off + 4 <= data.length && n++ < MAX_BTS_ACTIONS) {
			int type = (data[off] & 0xff) | ((data[off + 1] & 0xff) << 8);
			int size = (data[off + 2] & 0xff) | ((data[off + 3] & 0xff) << 8);
			int debut = off + 4;
			if (debut + size > data.length) {
				break;
			}
			if (type == 1 && size >= 4 && (data[debut] & 0xff) == 0x01) {
				int opcode = (data[debut + 1] & 0xff)
					| ((data[debut + 2] & 0xff) << 8);
				int plen = data[debut + 3] & 0xff;
				if (opcode == opcodeVoulu && plen >= 5
						&& debut + 4 + plen <= data.length) {
					int p = debut + 4;
					long addr = u32le(data, p);
					int len = data[p + 4] & 0xff;
					if (p + 5 + len <= data.length) {
						byte[] charge = new byte[len];
						System.arraycopy(data, p + 5, charge, 0, len);
						out.add(new BtsBlob(addr, charge));
					}
				}
			}
			off = debut + size;
		}
		return out;
	}

	/** 0xff05 = HCI_VS_Write_Memory_Block. Les morceaux contigus sont recolles. */
	public static List<BtsBlob> btsCodeBlobs(byte[] data) {
		List<BtsBlob> morceaux = new ArrayList<>(payloads(data, 0xff05));
		morceaux.sort((a, b) -> Long.compare(a.addr, b.addr));

		List<BtsBlob> blobs = new ArrayList<>();
		for (BtsBlob m : morceaux) {
			if (!blobs.isEmpty()) {
				BtsBlob dernier = blobs.get(blobs.size() - 1);
				if (m.addr == dernier.addr + dernier.data.length) {
					byte[] fusion = new byte[dernier.data.length + m.data.length];
					System.arraycopy(dernier.data, 0, fusion, 0, dernier.data.length);
					System.arraycopy(m.data, 0, fusion, dernier.data.length,
						m.data.length);
					blobs.set(blobs.size() - 1, new BtsBlob(dernier.addr, fusion));
					continue;
				}
			}
			blobs.add(m);
		}
		return blobs;
	}

	/** 0xff03 = ecriture memoire ponctuelle. */
	public static List<BtsBlob> btsPokes(byte[] data) {
		return payloads(data, 0xff03);
	}
}
