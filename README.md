# FishStop

FishStop è un'app desktop Tauri per analizzare localmente email `.eml` sospette. Combina controlli statici, verifica dell'identità del mittente, ispezione sicura di link e allegati e analisi semantica locale.

## Cosa fa

- Analizza header, catena di recapito, SPF/DKIM/DMARC, Reply-To e Return-Path.
- Individua domini lookalike, URL mascherati, redirect, download rischiosi e incongruenze tra richiesta e risorsa proposta.
- Ispeziona allegati e HTML senza eseguire script, form o contenuti remoti.
- Usa un modello NER locale per estrarre organizzazioni e confrontarne l'identità con i domini osservati.
- Usa in locale un modello Qwen approvato, scelto automaticamente in base alla piattaforma. Il corpo dell'email non viene inviato a servizi AI hosted.
- Può usare VirusTotal e AbuseIPDB, se configurati: vengono inviati solo indicatori tecnici, mai il file `.eml` o il suo contenuto.
- Può sincronizzare i Pulse sottoscritti e i Pulse pubblici recenti con tag `phishing` su AlienVault OTX: i feed vengono scaricati in background e URL, domini, IP e hash vengono poi confrontati localmente, senza chiamate OTX durante l'analisi.
- Dalla sezione `Analyse from inbox`, subito sotto `Analyse`, può collegare in sola lettura la casella Gmail o Outlook associata al login, vedere gli ultimi 10 messaggi e scaricare il MIME/EML soltanto quando viene scelto `Analyse`. Il refresh token resta nel portachiavi di sistema e l'email viene elaborata dalla pipeline locale esistente.

## Qwen locale

Qwen è il modello semantico predefinito e gestito da FishStop.

Apri **Settings → Qwen locale**:

- se il modello non è installato, è disponibile **Install Qwen**;
- se il modello è installato, è disponibile **Remove model**;
- il runtime e i modelli gestiti sono locali all'app.

La selezione manuale è disabilitata: FishStop usa `qwen3:4b-instruct-2507-q4_K_M` su tutte le piattaforme supportate.

L'analisi semantica usa per impostazione predefinita la modalità `balanced`: una passata primaria e, solo quando rimangono ambiguità rilevanti, un unico audit locale aggiuntivo. Per confronti di qualità si può impostare `FISHSTOP_ANALYSIS_MODE=fast|balanced|thorough`; `fast` disabilita l'audit e `thorough` conserva i controlli specializzati separati.

Sui computer CPU-only FishStop esegue Identity e Qwen in sequenza, assegna a Ollama i core fisici disponibili e usa un profilo con contesto e output limitati. Il modello resta caricato per 15 minuti e l'analisi AI ha un budget complessivo di 270 secondi; se non termina, i controlli statici rimangono disponibili e l'errore indica la fase effettiva del timeout.

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
.venv/bin/python scripts/export_identity_onnx.py
FISHSTOP_TARGET_TRIPLE=$(rustc --print host-tuple) .venv/bin/python scripts/build_sidecar.py
npm run tauri build
```

L'export genera in `build/identity-model/onnx` il modello multilingue GLiNER ONNX; il sidecar lo include automaticamente e mantiene un fallback PyTorch per lo sviluppo senza artefatto. GLiNER riceve etichette mirate a brand, aziende, servizi e istituzioni e analizza insieme mittente, oggetto e corpo. Il modello resta FP32 perché la quantizzazione dinamica di questa specifica variante degrada sensibilmente il riconoscimento dei brand. Il sidecar evita di richiedere Python all'utente finale. Qwen viene scaricato localmente solo quando l'utente lo installa dalle impostazioni.

## Accesso e dati locali

Gli accessi Google e Microsoft usano OAuth Authorization Code con PKCE e callback loopback locale. Microsoft usa un client desktop pubblico e non richiede un client secret; nel portale Entra deve essere registrato `http://localhost` come URI di reindirizzamento per applicazioni mobili e desktop. Non vengono salvate password. I token temporanei del login non vengono conservati; quando l'utente collega volontariamente la casella, il solo refresh token necessario a mantenere l'accesso in lettura viene custodito nel portachiavi di sistema e rimosso da FishStop con `Disconnect`. Anche le chiavi API di reputazione sono conservate nel portachiavi; cronologia, preferenze e cache OTX restano sul dispositivo e sono separate per provider e account. Dopo l'accesso FishStop aggiorna in background la cache OTX quando è assente, incompleta o più vecchia di 24 ore, quindi ripete il controllo ogni 24 ore finché l'app rimane aperta. Se il servizio è lento o non disponibile, conserva l'ultima copia valida e l'analisi non attende la rete.

Per abilitare la casella, nel progetto OAuth Google devono essere attivate Gmail API e la scope `gmail.readonly`; nell'app Microsoft Entra deve essere consentita la permission delegata `Mail.Read`. Google può richiedere la verifica della consent screen prima della distribuzione pubblica perché l'accesso Gmail è una scope restricted.
