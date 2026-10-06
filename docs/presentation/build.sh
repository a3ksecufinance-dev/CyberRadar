#!/usr/bin/env bash
# build.sh — construit la présentation PDF depuis sa source HTML, et la vérifie.
#
# Pourquoi une vérification et pas seulement une construction : une page coupée
# ne se voit pas dans le source, elle se voit en salle. Deux débordements réels
# ont été trouvés par `verifier.py` — un tableau de dix lignes qui passait sous
# le filet du pied de page, et une note qui le chevauchait — dont l'un venait
# d'être introduit par la correction de l'autre.
#
#   ./build.sh          construire et vérifier
#
# Chromium est celui de Playwright, déjà présent pour les tests de bout en bout.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHROMIUM="${CRP_CHROMIUM_PATH:-/opt/pw-browsers/chromium}"
[[ -x "$CHROMIUM" ]] || { echo "pas de Chromium à $CHROMIUM (CRP_CHROMIUM_PATH)" >&2; exit 1; }

cd "$HERE"
"$CHROMIUM" --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
	--print-to-pdf=CyberRadar-Presentation.pdf presentation.html 2>/dev/null
echo "→ CyberRadar-Presentation.pdf ($(stat -c %s CyberRadar-Presentation.pdf) octets)"

python3 verifier.py
