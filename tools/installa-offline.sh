#!/bin/sh
# Installa Varco SENZA internet, prendendo le dipendenze dal DVD 1 di Debian 13.
#
#   sh installa-offline.sh [percorso del file .iso]
#
# Senza percorso cerca debian-13*-amd64-DVD-1.iso in /home/kimiko/Scaricati.
#
# 1. controlla l'ISO con il file SHA512SUMS scaricato insieme: se manca si ferma
#    (per procedere lo stesso: SENZA_VERIFICA=1 sh installa-offline.sh);
# 2. monta l'ISO in sola lettura e la usa come unica fonte di pacchetti;
# 3. installa i tre pacchetti di Varco di questa versione e le loro dipendenze ufficiali;
# 4. smonta l'ISO e rimuove la fonte temporanea: le fonti apt normali non vengono toccate.
set -eu

VERSIONE=1.0.3
SCARICATI=/home/kimiko/Scaricati
DIR="$(cd "$(dirname "$0")" && pwd)"
MNT=/media/varco-debian-dvd
LIST=/etc/apt/sources.list.d/varco-dvd-temporaneo.list
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[ "$(id -u)" -eq 0 ] || { echo "Esegui come root."; exit 1; }

if [ $# -ge 1 ]; then
    ISO="$1"
else
    set -- "$SCARICATI"/debian-13*-amd64-DVD-1.iso
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        echo "Non trovo un'unica ISO debian-13*-amd64-DVD-1.iso in $SCARICATI."
        echo "Indica il percorso: sh $0 /percorso/del/file.iso"
        exit 1
    fi
    ISO="$1"
fi
[ -f "$ISO" ] || { echo "ISO non trovata: $ISO"; exit 1; }

DEBS=""
for p in varco varco-gtk varco-privacy; do
    f="$DIR/${p}_${VERSIONE}_all.deb"
    [ -f "$f" ] || { echo "Manca $f accanto a questo script."; exit 1; }
    DEBS="$DEBS $f"
done

VUOTA=""
pulisci() {
    rm -f "$LIST"
    if [ -n "$VUOTA" ]; then rmdir "$VUOTA" 2>/dev/null || true; fi
    if mountpoint -q "$MNT"; then umount "$MNT" || true; fi
    rmdir "$MNT" 2>/dev/null || true
}
trap pulisci EXIT
trap 'exit 130' INT TERM

# 1. integrità dell'ISO
SUMS="$(dirname "$ISO")/SHA512SUMS"
NOME="$(basename "$ISO")"
if [ -f "$SUMS" ]; then
    echo "Controllo l'integrità dell'ISO (un minuto circa)..."
    ATTESO="$(awk -v n="$NOME" '$2 == n || $2 == "*"n {print $1}' "$SUMS")"
    [ -n "$ATTESO" ] || { echo "SHA512SUMS non contiene $NOME."; exit 1; }
    REALE="$(sha512sum "$ISO" | awk '{print $1}')"
    if [ "$ATTESO" != "$REALE" ]; then
        echo "ATTENZIONE: l'ISO NON corrisponde a SHA512SUMS. Mi fermo."
        exit 1
    fi
    echo "ISO integra (SHA512 corrispondente)."
    if [ -f "$SUMS.sign" ] && command -v gpg >/dev/null 2>&1 && gpg --verify "$SUMS.sign" "$SUMS" >/dev/null 2>&1; then
        echo "Firma di SHA512SUMS verificata."
    else
        echo "Nota: la firma di SHA512SUMS non è stata verificata (serve la chiave Debian CD nel portachiavi):"
        echo "      l'ISO è integra, la sua provenienza è garantita dal download da www.debian.org (HTTPS)."
    fi
elif [ "${SENZA_VERIFICA:-}" = "1" ]; then
    echo "ATTENZIONE: SHA512SUMS non trovato, procedo senza verifica perché SENZA_VERIFICA=1."
else
    echo "SHA512SUMS non trovato accanto all'ISO: non posso verificare che sia integra. Mi fermo."
    echo "Scaricalo dalla stessa pagina dell'ISO in $(dirname "$ISO"), oppure procedi a tuo rischio con:"
    echo "  SENZA_VERIFICA=1 sh $0 $ISO"
    exit 1
fi

# 2. ISO come fonte temporanea di pacchetti
mkdir -p "$MNT"
mountpoint -q "$MNT" || mount -o loop,ro "$ISO" "$MNT"
[ -f "$MNT/dists/trixie/Release" ] || { echo "Questa ISO non è un DVD di Debian 13 (trixie)."; exit 1; }
COMP="$(awk -F': ' '/^Components:/ {print $2}' "$MNT/dists/trixie/Release")"
# trusted=yes: i DVD Debian non hanno un Release firmato; l'ISO è stata appena verificata
echo "deb [trusted=yes] file://$MNT trixie ${COMP:-main}" > "$LIST"
VUOTA="$(mktemp -d)"
APT="-o Dir::Etc::SourceList=$LIST -o Dir::Etc::SourceParts=$VUOTA -o APT::Get::List-Cleanup=0"

echo "Leggo l'elenco dei pacchetti del DVD..."
# shellcheck disable=SC2086
apt-get $APT update -qq

# 3. installazione
echo "Installo Varco $VERSIONE e le sue dipendenze dal DVD..."
# shellcheck disable=SC2086
if ! DEBIAN_FRONTEND=noninteractive apt-get $APT install -y --no-install-recommends $DEBS; then
    echo
    echo "Alcune dipendenze non sono sul DVD 1 (vedi sopra i nomi dei pacchetti)."
    echo "Si trovano sul DVD 2 o online: Varco non è stato installato, il sistema non è cambiato."
    exit 1
fi

echo
echo "Varco $VERSIONE installato senza internet."
echo "Prima di collegarti: apri «Varco» dal menu delle applicazioni e premi «Attiva…»."
