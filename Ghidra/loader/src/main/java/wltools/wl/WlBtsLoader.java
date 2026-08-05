/* Loader Ghidra pour le script d'init Bluetooth TI (TIInit_*.bts).
 *
 * Le .bts n'est pas un firmware mais la sequence HCI rejouee au boot. Le code
 * du coeur BT voyage dans les commandes vendor 0xff05, que TI appelle
 * HCI_VS_Write_Memory_Block, par morceaux de 240 octets. On les recolle ici.
 *
 * TODO teste seulement sur TIInit_11.8.32. Les 6.x et 7.x parsent bien (j'ai
 * verifie a la main) mais elles ont pas de 0xff03, du coup labelPokes est
 * jamais exerce dessus.
 */
package wltools.wl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

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
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

public class WlBtsLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "TI Bluetooth init script (.bts patch)";

	private static final String LANGUAGE = "ARM:LE:32:Cortex";

	private static final String OPT_MIN = "Taille minimale d un blob (octets)";
	private static final String OPT_POKES = "Etiqueter les ecritures memoire 0xff03";

	private static final int DEFAULT_MIN = 256;

	/** Taille de page creee pour les pokes qui tombent hors des blobs. */
	private static final long POKE_PAGE = 0x1000;

	@Override
	public String getName() {
		return NAME;
	}

	// magic proprietaire donc loader specialise, on passe devant Raw Binary
	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
			throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		byte[] data = LoaderUtil.readAll(provider);
		if (!WlFirmware.isBts(data)) {
			return specs;
		}
		// un .bts sans 0xff05 ne porte aucun code, rien a desassembler
		if (WlFirmware.btsCodeBlobs(data).isEmpty()) {
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
		int minSize = intOption(settings.options(), OPT_MIN, DEFAULT_MIN);
		boolean doPokes =
			LoaderUtil.optionEnabled(settings.options(), OPT_POKES, true);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		int made = 0;
		long total = 0;
		for (WlFirmware.BtsBlob blob : WlFirmware.btsCodeBlobs(data)) {
			if (blob.data.length < minSize) {
				continue;       // en dessous c'est du poke deguise, rien a desassembler
			}
			try {
				MemoryBlockUtils.createInitializedBlock(program, false,
					String.format("patch_%08x", blob.addr), LoaderUtil.addr(space, blob.addr),
					new ByteArrayInputStream(blob.data), blob.data.length,
					"patch de code BT", getName(), true, true, true,
					settings.log(), settings.monitor());
				made++;
				total += blob.data.length;
			}
			catch (Exception e) {
				settings.log().appendException(e);
			}
		}
		settings.log().appendMsg(getName(),
			String.format("%d blobs de patch charges, %d octets", made, total));

		if (doPokes) {
			settings.log().appendMsg(getName(), labelPokes(program, space, data, settings));
		}
	}

	private String labelPokes(Program program, AddressSpace space, byte[] data,
			ImporterSettings settings) {
		int posed = 0;
		int mapped = 0;
		for (WlFirmware.BtsBlob poke : WlFirmware.btsPokes(data)) {
			Address a = LoaderUtil.addr(space, poke.addr);
			// la plupart tombent dans les trous entre les blobs, et sans bloc
			// memoire derriere la reference se resout pas
			if (program.getMemory().getBlock(a) == null) {
				long base = poke.addr & ~(POKE_PAGE - 1);
				try {
					MemoryBlockUtils.createUninitializedBlock(program, false,
						String.format("bts_target_%08x", base),
						LoaderUtil.addr(space, base), POKE_PAGE,
						"cible d ecriture TIInit", getName(), true, true, false,
						settings.log());
					mapped++;
				}
				catch (Exception e) {
					continue;
				}
			}
			StringBuilder hex = new StringBuilder();
			for (byte b : poke.data) {
				hex.append(String.format("%02x", b & 0xff));
			}
			try {
				program.getSymbolTable().createLabel(a,
					String.format("bts_poke_%08x", poke.addr), SourceType.IMPORTED);
				program.getListing().setComment(a, CommentType.EOL,
					"ecrit par TIInit au boot : 0x" + hex);
				posed++;
			}
			catch (Exception e) {
				// deja nomme, on passe
			}
		}
		return String.format("%d ecritures memoire etiquetees (%d pages creees)",
			posed, mapped);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			isLoadIntoProgram, mirrorFsLayout);
		list.add(new Option(OPT_MIN, DEFAULT_MIN));
		list.add(new Option(OPT_POKES, Boolean.TRUE));
		return list;
	}

	private static int intOption(List<Option> options, String name, int fallback) {
		if (options == null) {
			return fallback;
		}
		for (Option o : options) {
			if (o.getName().equals(name) && o.getValue() instanceof Integer) {
				return (Integer) o.getValue();
			}
		}
		return fallback;
	}
}
