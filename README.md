# FishStop

FishStop è un'app desktop Tauri per analizzare localmente email `.eml` sospette. Combina controlli statici, verifica dell'identità del mittente, ispezione sicura di link e allegati e analisi semantica locale.

## Cosa fa

- Analizza header, catena di recapito, SPF/DKIM/DMARC, Reply-To e Return-Path.
- Individua domini lookalike, URL mascherati, redirect, download rischiosi e incongruenze tra richiesta e risorsa proposta.
- Ispeziona allegati e HTML senza eseguire script, form o contenuti remoti.
- Usa un modello NER locale per estrarre organizzazioni e confrontarne l'identità con i domini osservati.
- Usa in locale un modello Qwen approvato, scelto automaticamente in base alla piattaforma. Il corpo dell'email non viene inviato a servizi AI hosted.
- Può usare VirusTotal e AbuseIPDB, se configurati: vengono inviati solo indicatori tecnici, mai il file `.eml` o il suo contenuto.

## Qwen locale

Qwen è il modello semantico predefinito e gestito da FishStop.

Apri **Settings → Qwen locale**:

- se il modello non è installato, è disponibile **Install Qwen**;
- se il modello è installato, è disponibile **Remove model**;
- il runtime e i modelli gestiti sono locali all'app.

La selezione manuale è disabilitata: FishStop usa `qwen3:4b-q4_K_M` sui Mac Apple Silicon e `qwen3:4b-instruct-2507-q4_K_M` sui runtime CPU Windows e Linux.

## Avvio in sviluppo

Prerequisiti: Node.js LTS, Rust e Python 3.

```bash
npm install
python3 -m venv .venv
.venv/bin/pip install -r src-python/requirements.txt pyinstaller
npm run tauri dev
```

In modalità sviluppo FishStop esegue il motore da `src-python/main.py`, quindi le modifiche Python vengono usate direttamente dall'app. Se il runtime Ollama incluso non è disponibile nell'ambiente di sviluppo, puoi usare un'installazione locale di Ollama con un modello già scaricato.

## Build installabile

Il pacchetto include il motore Python come sidecar e il runtime Ollama richiesto dall'app. Prima del build crea il sidecar per l'architettura corrente:

```bash
.venv/bin/pip install -r src-python/requirements.txt pyinstaller
FISHSTOP_TARGET_TRIPLE=$(rustc --print host-tuple) .venv/bin/python scripts/build_sidecar.py
npm run tauri build
```

Il sidecar evita di richiedere Python all'utente finale. Qwen viene scaricato localmente solo quando l'utente lo installa dalle impostazioni.

## Accesso e dati locali

L'accesso Google usa OAuth Authorization Code con PKCE e callback su `127.0.0.1`. Non vengono salvati password o client secret dell'utente. Le chiavi API di reputazione sono conservate nel portachiavi di sistema; cronologia e preferenze restano sul dispositivo.
