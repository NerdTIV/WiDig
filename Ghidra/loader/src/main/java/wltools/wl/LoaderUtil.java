/* Petits utilitaires partages par les deux loaders TI.
 *
 * Les memes existent en double dans l'extension Qualcomm. C'est voulu, les
 * deux extensions doivent compiler chacune de leur cote.
 */
package wltools.wl;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public final class LoaderUtil {

	public static byte[] readAll(ByteProvider provider) throws IOException {
		long len = provider.length();
		if (len > Integer.MAX_VALUE) {
			throw new IOException("fichier trop gros pour ce loader");
		}
		return provider.readBytes(0, len);
	}

	public static Address addr(AddressSpace space, long value) {
		// masque sur 32 bits: les adresses du firmware sont des u32 et sans
		// ca le chunk a 0x80958000 part en negatif
		return space.getAddress(value & 0xffffffffL);
	}

	public static String clean(String name) {
		StringBuilder out = new StringBuilder();
		for (char c : name.toCharArray()) {
			out.append(Character.isLetterOrDigit(c) || c == '_' || c == '.' ? c : '_');
		}
		String s = out.toString();
		if (s.isEmpty()) {
			return "sans_nom";
		}
		return Character.isDigit(s.charAt(0)) ? "f_" + s : s;
	}

	public static boolean optionEnabled(List<Option> options, String name,
			boolean fallback) {
		if (options == null) {
			return fallback;
		}
		for (Option o : options) {
			if (o.getName().equals(name) && o.getValue() instanceof Boolean) {
				return (Boolean) o.getValue();
			}
		}
		return fallback;
	}
}
