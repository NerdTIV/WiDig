#!/bin/sh
# Compile et empaquette l'extension Ghidra des loaders TI WiLink.
#
#   ./build.sh            compile, jar, et fabrique dist/<nom>.zip
#   ./build.sh install    pareil + installe dans le dossier utilisateur Ghidra
#   ./build.sh clean      vire build/ dist/ et le jar
#
# Pas de gradle. Pour une extension de loaders javac + jar avec les jars de
# Ghidra au classpath ca suffit largement.
#
# Variables: GHIDRA_INSTALL_DIR, JAVA_HOME

set -e

NAME=TIWirelessLoaders
HERE=$(cd "$(dirname "$0")" && pwd)
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/ghidra_12.1.2_PUBLIC}

BUILD="$HERE/build"
DIST="$HERE/dist"

# les rm -rf plus bas visent des chemins construits a partir de variables.
# Si une des variables est vide on efface une racine. Donc on verifie avant,
# c'est pas de la parano.
die() { echo "[!] $1" >&2; exit 1; }

[ -n "$NAME" ] || die "NAME vide"
[ -n "$HERE" ] && [ -d "$HERE" ] || die "HERE invalide : '$HERE'"
case "$BUILD" in "$HERE"/*) ;; *) die "BUILD hors du dossier : '$BUILD'" ;; esac
case "$DIST"  in "$HERE"/*) ;; *) die "DIST hors du dossier : '$DIST'" ;; esac

if [ "$1" = "clean" ]; then
    rm -rf "$BUILD" "$DIST" "$HERE/lib/$NAME.jar"
    echo "[+] nettoye"
    exit 0
fi

[ -d "$GHIDRA" ] || die "GHIDRA_INSTALL_DIR introuvable : $GHIDRA"

if [ -n "$JAVA_HOME" ]; then
    JAVAC="$JAVA_HOME/bin/javac"; JAR="$JAVA_HOME/bin/jar"
else
    JAVAC=javac; JAR=jar
fi

VERSION=$(sed -n 's/^application\.version=//p' "$GHIDRA/Ghidra/application.properties")
[ -n "$VERSION" ] || VERSION=12.1.2

# on prend tous les jars de Ghidra. Plus simple que de lister les modules,
# qui bougent d'une version a l'autre.
CP=$(find "$GHIDRA/Ghidra" -name '*.jar' | tr '\n' ':')

echo "[*] $NAME  -  Ghidra $VERSION"
rm -rf "$BUILD"
mkdir -p "$BUILD/classes" "$HERE/lib" "$DIST"

find "$HERE/src/main/java" -name '*.java' > "$BUILD/sources.txt"
"$JAVAC" -nowarn -d "$BUILD/classes" -cp "$CP" @"$BUILD/sources.txt"
"$JAR" cf "$HERE/lib/$NAME.jar" -C "$BUILD/classes" .

# Layout attendu: extension.properties, Module.manifest, lib/<NAME>.jar
# Le Module.manifest doit rester VIDE. Une ligne MODULE FILE LICENSE qui
# pointe sur un fichier absent fait rejeter le module, sans message nulle
# part. 2h de perdues.
STAGE="$BUILD/stage/$NAME"
mkdir -p "$STAGE/lib"
sed -e "s/@extname@/$NAME/" -e "s/@extversion@/$VERSION/" \
    "$HERE/extension.properties" > "$STAGE/extension.properties"
: > "$STAGE/Module.manifest"
cp "$HERE/lib/$NAME.jar" "$STAGE/lib/"

ZIP="$DIST/ghidra_${VERSION}_${NAME}.zip"
rm -f "$ZIP"
(cd "$BUILD/stage" && zip -qr "$ZIP" "$NAME")
echo "[+] $ZIP"

if [ "$1" = "install" ]; then
    # Ghidra 12 est passe aux repertoires XDG. Une extension posee dans
    # l'ancien ~/.ghidra est ignoree sans rien dire, on s'en apercoit
    # seulement au ClassNotFoundException.
    XDG=${XDG_CONFIG_HOME:-$HOME/.config}
    if [ -d "$XDG/ghidra/ghidra_${VERSION}_PUBLIC" ]; then
        DEST="$XDG/ghidra/ghidra_${VERSION}_PUBLIC/Extensions"
    elif [ -d "$HOME/.ghidra/.ghidra_${VERSION}_PUBLIC" ]; then
        DEST="$HOME/.ghidra/.ghidra_${VERSION}_PUBLIC/Extensions"   # Ghidra <= 11
    else
        DEST="$XDG/ghidra/ghidra_${VERSION}_PUBLIC/Extensions"
    fi
    # on supprime <Extensions>/<NAME>, surtout pas <Extensions>
    case "$DEST" in */Extensions) ;; *) die "DEST inattendu : '$DEST'" ;; esac
    mkdir -p "$DEST"
    [ -d "$DEST/$NAME" ] && rm -rf "$DEST/$NAME"
    cp -r "$STAGE" "$DEST/$NAME"
    echo "[+] installe dans $DEST/$NAME"
    echo "    redemarrer Ghidra (une extension n'est pas rechargee a chaud)"
fi
