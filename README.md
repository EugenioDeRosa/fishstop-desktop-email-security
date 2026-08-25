# FishStop

App desktop per l'analisi di email `.eml` sospette. Include parsing statico locale, classificazione DistilBERT e analisi semantica Phi-4 mini.

## Avvio locale

1. Installa Node.js LTS e Rust.
2. Esegui `npm install`.
3. Installa il motore Python e PyInstaller: `python3 -m pip install -r src-python/requirements.txt pyinstaller`.
4. Crea il sidecar per la tua architettura: `FISHSTOP_TARGET_TRIPLE=$(rustc --print host-tuple) python3 scripts/build_sidecar.py`.
5. Per l'analisi Phi-4 locale, avvia Ollama con il modello configurato in `OLLAMA_MODEL` (di default `phi4-mini:3.8b-q4_K_M`).
6. Esegui `npm run tauri dev`.

## Build installabile

La pipeline GitHub Actions crea il motore Python come sidecar e lo include
nell'installer. Per pubblicare una release, aggiorna la versione in
`package.json` e `src-tauri/tauri.conf.json`, poi crea e invia un tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

La workflow `.github/workflows/publish-desktop.yml` genera gli installer per
Mac Intel, Apple Silicon e Windows e crea una GitHub Release in bozza. Dopo la
verifica, pubblica la bozza: la pagina Streamlit di FishSTOP rileverà i file
`.dmg` e `.msi` automaticamente.

Per un test locale, prima crea il sidecar per la tua architettura e poi avvia
il build Tauri:

```bash
python3 -m pip install -r src-python/requirements.txt pyinstaller
FISHSTOP_TARGET_TRIPLE=$(rustc --print host-tuple) python3 scripts/build_sidecar.py
npm run tauri build
```

Il sidecar elimina il requisito di installare Python sul computer dell'utente.
Ollama resta necessario per le funzionalità Phi-4 locali.

## Motori AI

- **DistilBERT** scarica al primo utilizzo il modello FishStop da Hugging Face e applica la stessa calibrazione dell'app Streamlit.
- **Phi-4 mini** usa esclusivamente Ollama locale. Se Ollama o il modello non sono disponibili, l'analisi semantica viene segnalata come non disponibile.
- Il contenuto email resta sul dispositivo: FishStop non usa backend AI hosted per Phi-4.

## Accesso Google

Il Client ID pubblico dell'app desktop è configurato nel backend Tauri. L'accesso apre il browser predefinito e riceve il callback su `127.0.0.1` usando OAuth Authorization Code con PKCE. Non vengono salvati password, client secret o token su disco.
