#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Construit une fiche PDF par module, et le recueil complet.

La mise en page vit ici, le contenu dans modules.py. Une correction de forme
profite aux seize fiches, ce qui est la seule façon de ne pas les voir diverger.

    ./build.py            construire les fiches et le recueil, puis vérifier
    ./build.py --only siem  une seule, pour itérer vite
"""
import base64, html, importlib.util, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).parent
CHROMIUM = "/opt/pw-browsers/chromium"

spec = importlib.util.spec_from_file_location("modules", HERE / "modules.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

CSS = """
@page { size: 210mm 297mm; margin: 0; }
*{box-sizing:border-box;margin:0;padding:0}
html,body{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-family:"DejaVu Sans","Liberation Sans",Helvetica,Arial,sans-serif;color:#0B1220;
     font-variant-numeric:tabular-nums}
.page{width:210mm;height:297mm;page-break-after:always;position:relative;
      padding:22mm 20mm 18mm;background:#fff;overflow:hidden}
.page:last-child{page-break-after:auto}
.eyebrow{font-size:9pt;letter-spacing:.16em;text-transform:uppercase;color:#1D4ED8;font-weight:700}
h1{font-size:30pt;line-height:1.05;letter-spacing:-.02em;margin:5mm 0 3mm}
h2{font-size:16pt;letter-spacing:-.01em;margin:0 0 3mm}
h3{font-size:11pt;margin:0 0 1.5mm}
.lead{font-size:12.5pt;line-height:1.5;color:#3C4659;max-width:62ch}
p{font-size:10.5pt;line-height:1.55;color:#3C4659}
.foot{position:absolute;left:20mm;right:20mm;bottom:12mm;display:flex;
      justify-content:space-between;font-size:8pt;color:#8B94A3;border-top:1px solid #E4E7EC;
      padding-top:3mm;letter-spacing:.04em}
.foot b{color:#5B6472;font-weight:600}
.band{background:#0B1220;color:#fff;margin:-22mm -20mm 0;padding:16mm 20mm 12mm}
.band .eyebrow{color:#7FA0F5}.band h1{color:#fff}.band .lead{color:#AFBACB}
.card{background:#F6F8FB;border:1px solid #E4E7EC;border-radius:3mm;padding:5mm 6mm;margin-bottom:4mm}
.card p{font-size:10pt}
.grid{display:grid;gap:4mm;margin-top:5mm}
.g2{grid-template-columns:1fr 1fr}
.shot{width:100%;border:1px solid #D9DEE7;border-radius:2mm;display:block}
.cap{font-size:8.5pt;color:#8B94A3;margin-top:2.5mm;font-style:italic}
ol{counter-reset:s;list-style:none;margin-top:3mm}
ol li{counter-increment:s;position:relative;padding-left:9mm;margin-bottom:3.5mm;
      font-size:10.5pt;line-height:1.5;color:#3C4659}
ol li:before{content:counter(s);position:absolute;left:0;top:0;width:6mm;height:6mm;
  border-radius:50%;background:#1D4ED8;color:#fff;font-size:8.5pt;font-weight:700;
  display:flex;align-items:center;justify-content:center}
dl{margin-top:3mm}
dt{font-size:10.5pt;font-weight:700;margin-top:3.5mm}
dd{font-size:10pt;line-height:1.5;color:#3C4659;margin-top:.8mm}
.adv{border-left:3px solid #047857;padding:1mm 0 1mm 5mm;margin-bottom:4.5mm}
.adv b{font-size:11pt;display:block;margin-bottom:1mm}
.adv span{font-size:10pt;line-height:1.5;color:#3C4659}
.note{border-left:3px solid #B45309;padding:1mm 0 1mm 5mm;font-size:9.5pt;
      line-height:1.5;color:#3C4659;margin-top:5mm}
.tag{display:inline-block;background:#E8EEFD;color:#1D4ED8;font-size:8.5pt;font-weight:700;
     padding:1mm 3mm;border-radius:10mm;letter-spacing:.04em}
"""

def esc(t): return html.escape(t, quote=False)

def img64(p):
    return "data:image/png;base64," + base64.b64encode(pathlib.Path(p).read_bytes()).decode()

def fiche(d, page_of=None):
    """Les trois pages d'un module."""
    shot = HERE / "captures" / f"{d['slug']}.png"
    n = lambda i: f"{i}" if page_of is None else f"{page_of[0]+i-1} / {page_of[1]}"
    foot = lambda i: (f'<div class="foot"><b>CyberRadar · {esc(d["titre"])}</b>'
                      f'<span>{n(i)}</span></div>')
    lect = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in d["lecture"])
    meca = "".join(f"<li>{esc(x)}</li>" for x in d["mecanisme"])
    avan = "".join(f'<div class="adv"><b>{esc(t)}</b><span>{esc(x)}</span></div>'
                   for t, x in d["avantages"])
    return f"""
<section class="page">
  <div class="band">
    <div class="eyebrow">{esc(d['famille'])}</div>
    <h1>{esc(d['titre'])}</h1>
    <p class="lead">{esc(d['accroche'])}</p>
  </div>
  <h2 style="margin-top:14mm">Le problème</h2>
  <p>{esc(d['probleme'])}</p>
  <h2 style="margin-top:9mm">Ce que fait le module</h2>
  <p>{esc(d['quoi'])}</p>
  {foot(1)}
</section>
<section class="page">
  <div class="eyebrow">{esc(d['titre'])}</div>
  <h2 style="margin:4mm 0 5mm">L'écran, tel qu'il est</h2>
  <img class="shot" src="{img64(shot)}" alt="{esc(d['titre'])}">
  <p class="cap">Capture réelle de la plateforme — Banque Al Massira, jeu de démonstration
     (125 actifs, 24 agences). Aucune retouche.</p>
  <h2 style="margin-top:8mm">Ce que l'écran montre</h2>
  <dl>{lect}</dl>
  {foot(2)}
</section>
<section class="page">
  <div class="eyebrow">{esc(d['titre'])}</div>
  <h2 style="margin:4mm 0 2mm">Comment ça marche</h2>
  <ol>{meca}</ol>
  <h2 style="margin-top:10mm">Ce que le client y gagne</h2>
  <div style="margin-top:4mm">{avan}</div>
  <div class="note"><b>Souveraineté.</b> Ce module fonctionne entièrement sur votre
    infrastructure. Aucun flux sortant n'est nécessaire à son fonctionnement.</div>
  {foot(3)}
</section>"""

def doc(body, titre):
    return (f'<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            f'<title>{esc(titre)}</title><style>{CSS}</style></head><body>{body}</body></html>')

def render(html_text, out):
    src = HERE / ".build.html"
    src.write_text(html_text)
    subprocess.run([CHROMIUM, "--headless", "--disable-gpu", "--no-sandbox",
                    "--no-pdf-header-footer", f"--print-to-pdf={out}", str(src)],
                   check=True, capture_output=True)
    src.unlink()

def main():
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]
    fiches = HERE / "fiches"
    fiches.mkdir(exist_ok=True)
    produced = []
    for d in mod.MODULES:
        if only and d["slug"] != only:
            continue
        out = fiches / f"CyberRadar-{d['slug']}.pdf"
        render(doc(fiche(d), f"CyberRadar — {d['titre']}"), out)
        produced.append((d, out))
        print(f"  {d['slug'].ljust(16)} → {out.name} ({out.stat().st_size // 1024} Ko)")

    if not only:
        # Le recueil : les seize fiches à la suite, numérotées en continu.
        body, page = "", 1
        for d in mod.MODULES:
            body += fiche(d, page_of=(page, len(mod.MODULES) * 3))
            page += 3
        out = HERE / "CyberRadar-Modules.pdf"
        render(doc(body, "CyberRadar — Les modules"), out)
        print(f"\n  recueil complet → {out.name} ({out.stat().st_size // 1024} Ko)")

    # Vérifier ce qu'on vient de produire, et non la version d'avant : une
    # page coupée se voit en salle, chez le client, et nulle part ailleurs.
    print()
    spec_v = importlib.util.spec_from_file_location("verifier", HERE / "verifier.py")
    ver = importlib.util.module_from_spec(spec_v); spec_v.loader.exec_module(ver)
    faults = sum(ver.check(out) for _, out in produced)
    if not only:
        faults += ver.check(HERE / "CyberRadar-Modules.pdf")
    if faults:
        print(f"\n{faults} débordement(s) — à corriger avant diffusion")
        sys.exit(1)
    return produced

if __name__ == "__main__":
    main()
