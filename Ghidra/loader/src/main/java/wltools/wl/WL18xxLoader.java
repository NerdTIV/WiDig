/* Loader Ghidra pour les firmwares WiFi TI WiLink.
 *
 * Le fichier est pas une image plate, c'est une liste de chunks prefixes
 * adresse/taille en big endian. Si on l'ouvre brut a l'adresse 0 tout est
 * decale et rien se desassemble, d'ou le loader plutot qu'un script.
 *
 * Teste sur les 18 firmwares TI de linux-firmware: 16 acceptes (wl18xx en 15
 * chunks, wl127x/wl128x en 6). wl1251 et cc33xx ont un autre conteneur, pas
 * regarde.
 */
package wltools.wl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

public class WL18xxLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "TI WiLink firmware (chunked)";

	// toute la gamme WiLink est en Cortex-M, donc du Thumb
	private static final String LANGUAGE = "ARM:LE:32:Cortex";

	private static final String OPT_TRACES = "Nommer les fonctions depuis la base de traces";
	private static final String OPT_VECTORS = "Poser les vecteurs Cortex-M";

	private static final String[] CORTEX_VECTORS = { "Reset_Handler", "NMI_Handler",
		"HardFault_Handler", "MemManage_Handler", "BusFault_Handler",
		"UsageFault_Handler", "Reserved_7", "Reserved_8", "Reserved_9", "Reserved_10",
		"SVC_Handler", "DebugMon_Handler", "Reserved_13", "PendSV_Handler",
		"SysTick_Handler" };

	@Override
	public String getName() {
		return NAME;
	}

	// format reconnu par magic, donc on passe devant Raw Binary qui lui
	// accepte n'importe quoi
	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
			throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		byte[] data = LoaderUtil.readAll(provider);
		List<WlFirmware.Chunk> chunks = WlFirmware.parseChunks(data);
		if (!WlFirmware.looksLikeFirmware(data, chunks)) {
			return specs;
		}
		specs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair(LANGUAGE, "default"), true));
		return specs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		byte[] data = LoaderUtil.readAll(settings.provider());
		List<WlFirmware.Chunk> chunks = WlFirmware.parseChunks(data);
		List<WlFirmware.Trace> traces = WlFirmware.parseTraces(data, chunks);
		Set<Integer> codeChunks = WlFirmware.codeChunks(data, chunks, traces);

		boolean doVectors = LoaderUtil.optionEnabled(settings.options(), OPT_VECTORS, true);
		boolean doTraces = LoaderUtil.optionEnabled(settings.options(), OPT_TRACES, true);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		// un bloc par chunk, a sa vraie adresse
		int faits = 0;
		for (WlFirmware.Chunk chunk : chunks) {
			// parseChunks a deja verifie que size tient dans le fichier, donc
			// le cast est sur ici
			byte[] body = new byte[(int) chunk.size];
			System.arraycopy(data, (int) chunk.fileOffset, body, 0, (int) chunk.size);

			boolean isCode = codeChunks.contains(chunk.index);
			try {
				MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
					chunk.blockName(), LoaderUtil.addr(space, chunk.addr),
					new ByteArrayInputStream(body), chunk.size,
					"chunk " + chunk.index, getName(), true, true, isCode,
					settings.log(), settings.monitor());
				if (block != null) {
					faits++;
				}
			}
			catch (Exception e) {
				settings.log().appendException(e);
			}
		}
		settings.log().appendMsg(getName(),
			String.format("%d blocs memoire crees sur %d chunks", faits, chunks.size()));

		// les vecteurs Cortex-M sont dans le chunk 0
		if (doVectors) {
			settings.log().appendMsg(getName(),
				String.format("%d vecteurs Cortex-M etiquetes",
					labelVectors(program, space, data, chunks)));
		}

		// et la base de traces, quand il y en a une
		if (doTraces && !traces.isEmpty()) {
			settings.log().appendMsg(getName(), labelTraces(program, space, traces));
		}
		else if (traces.isEmpty()) {
			settings.log().appendMsg(getName(),
				"pas de base de traces dans ce firmware : carte memoire et "
					+ "vecteurs poses, mais aucun symbole a recuperer");
		}
	}

	/**
	 * Un commentaire par site de trace, un label par nom de fonction.
	 *
	 * Le label va sur le site d'appel et pas sur l'entree de fonction: a ce
	 * stade on connait pas encore les bornes. C'est ghidra_wl.py qui remonte
	 * au prologue apres coup.
	 */
	private String labelTraces(Program program, AddressSpace space,
			List<WlFirmware.Trace> traces) {
		Map<String, Long> vus = new HashMap<>();
		int commentaires = 0;
		int labels = 0;

		for (WlFirmware.Trace t : traces) {
			Address a = LoaderUtil.addr(space, t.addr);
			if (program.getMemory().getBlock(a) == null) {
				continue;   // une dizaine pointent hors des chunks, tant pis
			}
			try {
				program.getListing().setComment(a, CommentType.EOL,
					String.format("%s:%d %s()  %s", t.source, t.line, t.func,
						t.fmt.trim()));
				commentaires++;
			}
			catch (Exception e) {
				// pas grave, on continue
			}
			// un seul label par nom de fonction, sinon on en pose 963
			if (vus.putIfAbsent(t.func, t.addr) == null) {
				try {
					program.getSymbolTable().createLabel(a,
						"trace_" + LoaderUtil.clean(t.func), SourceType.IMPORTED);
					labels++;
				}
				catch (Exception e) {
					// collision de nom
				}
			}
		}
		return String.format(
			"%d traces : %d commentaires, %d labels de site (%d noms de fonction)",
			traces.size(), commentaires, labels, vus.size());
	}

	private int labelVectors(Program program, AddressSpace space, byte[] data,
			List<WlFirmware.Chunk> chunks) {
		WlFirmware.Chunk chunk0 = null;
		for (WlFirmware.Chunk c : chunks) {
			if (c.contains(0)) {
				chunk0 = c;
				break;
			}
		}
		if (chunk0 == null) {
			return 0;
		}

		int poses = 0;
		for (int i = 1; i < 48; i++) {
			long off = chunk0.fileOffset + i * 4L;
			if (off + 4 > data.length || i * 4L + 4 > chunk0.size) {
				break;
			}
			int base = (int) off;
			long val = (data[base] & 0xffL) | ((data[base + 1] & 0xffL) << 8)
				| ((data[base + 2] & 0xffL) << 16) | ((data[base + 3] & 0xffL) << 24);
			if (val == 0 || val == 0xffffffffL || (val & 1) == 0) {
				continue;       // vecteur valide = impair (bit Thumb)
			}
			Address cible = LoaderUtil.addr(space, val & ~1L);
			if (program.getMemory().getBlock(cible) == null) {
				continue;
			}
			String nom = (i - 1 < CORTEX_VECTORS.length) ? CORTEX_VECTORS[i - 1]
					: ("IRQ_" + (i - 16) + "_Handler");
			try {
				program.getSymbolTable().createLabel(cible, nom, SourceType.IMPORTED);
				program.getListing().setComment(
					LoaderUtil.addr(space, chunk0.addr + i * 4L),
					CommentType.EOL, "vecteur " + nom);
				poses++;
			}
			catch (Exception e) {
				// deja nomme
			}
		}
		return poses;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			isLoadIntoProgram, mirrorFsLayout);
		list.add(new Option(OPT_VECTORS, Boolean.TRUE));
		list.add(new Option(OPT_TRACES, Boolean.TRUE));
		return list;
	}
}
