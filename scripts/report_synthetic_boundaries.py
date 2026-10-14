"""Render a compact diagnostic report from saved local evaluation results."""
import json,statistics
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'output/synthetic-boundaries-v1';DATA=json.loads((OUT/'results.json').read_text(encoding='utf-8'));LABELS={r['id']:r for r in map(json.loads,(ROOT/'evaluation/synthetic-boundaries-v1/labels.jsonl').read_text(encoding='utf-8').splitlines())}
PHASES=['direct','pipeline'];results={(r['phase'],r['id']):r for r in DATA['results']}
lines=['# Valutazione del modello base Fast — casi sintetici','', 'Data: 12 ottobre 2026. Modello base locale quantizzato Q4_K_M, senza fine-tuning. Set: 32 email nuove, 15 malevole, 15 legittime, 2 da verificare.','', 'Due prove distinte: classificazione diretta con prompt neutro e pipeline balanced attuale di FishSTOP. La seconda include parsing statico, verificatori semantici e policy applicative; il suo verdetto non misura soltanto il modello. Nessun controllo live di reputazione, nessuna apertura dei link.','', '## Risultati','', '| Prova | Completati | Malevole rilevate | Malevole classificate legittime | Malevole da verificare | Legittime classificate phishing | Legittime da verificare | Corrette sui 30 casi decidibili | Tempo mediano |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']
for phase in PHASES:
 rows=[r for r in DATA['results'] if r['phase']==phase]; good=[r for r in rows if r.get('status')=='ok'];counter=lambda e,p:sum(r['expected']==e and r.get('prediction')==p for r in rows); closed=[r for r in rows if r['expected']!='review'];correct=sum(r['expected']==r.get('prediction') for r in closed);med=f"{statistics.median(r['seconds'] for r in good):.1f} s" if good else '—'
 lines.append(f"| {'Modello diretto' if phase=='direct' else 'FishSTOP'} | {len(rows)}/32 | {counter('phishing','phishing')}/15 | {counter('phishing','legitimate')} | {counter('phishing','review')} | {counter('legitimate','phishing')} | {counter('legitimate','review')} | {correct}/{len(closed)} | {med} |")
lines+=['','## Dettaglio dei casi','','| ID | Categoria | Atteso | Modello diretto | FishSTOP |','|---|---|---|---|---|']
for id,l in LABELS.items():
 verdicts=[results.get((phase,id),{}).get('prediction','errore' if results.get((phase,id),{}).get('error') else 'non eseguito') for phase in PHASES]
 lines.append(f"| {id} | {l['category']} | {l['label']} | {verdicts[0]} | {verdicts[1]} |")
lines+=['','## Errori e interpretazioni da esaminare','']
for phase in PHASES:
 for r in DATA['results']:
  if r['phase']!=phase or r['expected']==r.get('prediction'):continue
  a=r.get('answer') or r.get('analysis') or {};reason=a.get('explanation') or r.get('error') or ''
  lines += [f"- **{r['id']} / {phase}**: atteso {r['expected']}, ottenuto {r.get('prediction','errore')}. {reason}"]
lines+=['','## Limiti della misura','', '- Le etichette esprimono l’intento nel contesto scritto; le email legittime non sono certificate da verifiche DNS o identità live.', '- La prova applicativa usa il parser statico e il motore semantico: non è un test completo della UI, della scelta interattiva delle conversazioni o della reputazione online.', '- Un verdetto review è una mancata decisione, non un phishing rilevato. Sulle email legittime può creare attrito senza essere un falso allarme phishing.', '- Set artificiale, breve e bilanciato: percentuali diagnostiche, non stima della qualità in produzione.', '- Le due prove impiegano prompt e formati di risposta diversi. Un divario indica un’interazione con prompt/parser/policy, non dimostra da solo la causa.', '- Temperature zero e seed fisso. I tempi includono richieste locali e possono variare con carico del computer e caricamento iniziale.', '- Tenere queste email fuori dal training. Per il fine-tuning generare varianti indipendenti e rivalutare sullo stesso holdout.', '- Il caso QR valuta la richiesta nel testo; non è un test di riconoscimento ottico di un QR. Gli HTML allegati sono inerti e non contengono malware eseguibile.','']
(OUT/'REPORT.md').write_text('\n'.join(lines),encoding='utf-8');print(OUT/'REPORT.md')
