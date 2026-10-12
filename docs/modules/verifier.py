# -*- coding: utf-8 -*-
"""Le contrôle de débordement des fiches.

Une page coupée ne se voit pas dans le source : elle se voit en salle, sur le
vidéoprojecteur d'un client. Le pied de page est une bande de hauteur connue,
alors tout texte qui y entre sans être le pied de page est du contenu qui a
débordé — et un bloc qui sort du rectangle de la page est une capture ou un
tableau trop large.

    python3 verifier.py                  vérifie le recueil et les seize fiches
    python3 verifier.py fiches/x.pdf     un fichier précis
"""
import pathlib, re, sys

import pymupdf

HERE = pathlib.Path(__file__).parent

# Le pied de page porte « CyberRadar · <titre> » à gauche et son numéro à
# droite — « 7 / 48 » dans le recueil, « 2 » dans une fiche isolée. Les deux
# formes sont reconnues par leur forme et non par le nombre de pages, qui
# change dès qu'un module est ajouté.
FOOTER = re.compile(r'^(CyberRadar\s·|\d{1,3}(\s*/\s*\d{1,3})?$)')

# Le filet du pied de page, mesuré sur la page rendue. Un seuil plus permissif
# laissait passer une dernière ligne de tableau qui touchait le filet.
FOOT_BAND = 62.0


def check(path: pathlib.Path) -> int:
    doc = pymupdf.open(path)
    bad = 0
    for i, page in enumerate(doc, 1):
        h, w = page.rect.height, page.rect.width
        for x0, y0, x1, y1, text, *_ in page.get_text("blocks"):
            text = text.strip()
            if not text or FOOTER.match(text):
                continue
            if y1 > h - FOOT_BAND:
                print(f"{path.name} p.{i:2d} : déborde dans le pied de page — {text[:70]!r}")
                bad += 1
            if y1 > h + 1 or x1 > w + 1:
                print(f"{path.name} p.{i:2d} : sort de la page — {text[:70]!r}")
                bad += 1
    print(f"  {path.name.ljust(34)} {doc.page_count:3d} pages, {bad} débordement(s)")
    return bad


def main(argv):
    targets = [pathlib.Path(a) for a in argv[1:]]
    if not targets:
        targets = [HERE / "CyberRadar-Modules.pdf", *sorted((HERE / "fiches").glob("*.pdf"))]
    total = sum(check(t) for t in targets if t.exists())
    if total:
        print(f"\n{total} débordement(s) — à corriger avant diffusion")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
