# Un contrôle de débordement, parce qu'une page coupée se voit en salle et pas
# dans le source : le pied de page est une bande connue, et tout texte qui y
# entre sans être le pied de page est du contenu qui déborde.
import pymupdf, sys

FOOT_TOP = 660.0 * 540 / 720   # la bande du pied de page, en points
doc = pymupdf.open("CyberRadar-Presentation.pdf")
bad = 0
for i, page in enumerate(doc, 1):
    h = page.rect.height
    foot_band = h - 62          # le filet du pied de page, mesuré sur la page
    for b in page.get_text("blocks"):
        x0, y0, x1, y1, text = b[0], b[1], b[2], b[3], b[4].strip()
        if not text:
            continue
        # le pied de page lui-même : il contient le numéro de page
        if f"/ 18" in text or "AUSIM 2026 —" in text or text.startswith("CyberRadar ·") or text == "CyberRadar":
            continue
        if y1 > foot_band:
            print(f"page {i:2d} : déborde dans le pied de page — {text[:70]!r}")
            bad += 1
        if y1 > h + 1 or x1 > page.rect.width + 1:
            print(f"page {i:2d} : sort de la page — {text[:70]!r}")
            bad += 1
print(f"\n{doc.page_count} pages, {bad} débordement(s)")
sys.exit(1 if bad else 0)
