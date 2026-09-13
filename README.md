# FishStop

FishStop è un'app desktop per macOS e Windows che analizza email sospette in formato `.eml`. Combina controlli tecnici, reputazione degli indicatori e analisi semantica locale per riconoscere phishing, truffe e Business Email Compromise senza inviare il contenuto dell'email a servizi AI esterni.

Versione attuale: **1.0.0**.

## Funzionalità principali

- Analisi di header, catena di recapito, SPF, DKIM, DMARC, `Reply-To` e `Return-Path`.
- Rilevamento di domini lookalike, URL mascherati, redirect, download rischiosi e incongruenze tra la richiesta e la risorsa proposta.
- Ispezione sicura di HTML e allegati, senza eseguire script, form o contenuti remoti.
- Analisi locale dell'identità dichiarata e dell'intento del messaggio tramite un modello Qwen gestito automaticamente da FishStop.
- Riconoscimento delle conversazioni incorporate nelle email inoltrate o nelle risposte: prima dell'analisi è possibile scegliere quali messaggi valutare e quali includere soltanto come contesto.
- Controlli di reputazione con VirusTotal, AbuseIPDB e AlienVault OTX. Ai servizi esterni vengono inviati esclusivamente indicatori tecnici compatibili con ciascun servizio, mai il file `.eml` o il testo dell'email.
- Importazione di un file `.eml` tramite selezione o trascinamento, fino a 40 MB.
- Collegamento facoltativo e in sola lettura della casella Gmail o Outlook associata all'accesso. FishStop mostra gli ultimi 10 messaggi e scarica il MIME/EML completo solo quando si avvia l'analisi.
- Cronologia locale, statistiche per periodo, report tecnico consultabile ed esportazione JSON.

## Scaricare FishStop

Gli installer aggiornati sono disponibili nella pagina [FishSTOP Latest](https://github.com/EugenioDeRosa/fishstop-desktop-email-security/releases/latest).

FishStop viene distribuito per:

- macOS con Apple Silicon (`aarch64`);
- macOS con processore Intel (`x64`);
- Windows a 64 bit (`x64`).

Il primo avvio e la configurazione iniziale richiedono una connessione Internet. Il modello AI occupa diversi GB e viene scaricato separatamente dall'app, solo su richiesta dell'utente.

## Installazione su macOS

1. Apri il menu Apple ** → Informazioni su questo Mac** e controlla la voce **Chip** o **Processore**.
2. Apri la pagina [FishSTOP Latest](https://github.com/EugenioDeRosa/fishstop-desktop-email-security/releases/latest) e scarica il file corretto:
   - `FishStop_*_aarch64.dmg` per Mac con chip Apple Silicon (M1, M2, M3, M4 o successivi);
   - `FishStop_*_x64.dmg` per Mac con processore Intel.
3. Apri il file `.dmg` appena scaricato.
4. Trascina **FishStop** nella cartella **Applicazioni**.
5. Espelli l'immagine disco e avvia FishStop da **Applicazioni**.

Se macOS blocca il primo avvio perché non riconosce lo sviluppatore, apri **Impostazioni di Sistema → Privacy e sicurezza**, individua il messaggio relativo a FishStop e scegli **Apri comunque**. Esegui questa operazione soltanto se hai scaricato l'app dalla release ufficiale indicata sopra.

> Gli archivi `.app.tar.gz` presenti nella release sono artefatti di distribuzione. Per l'installazione normale usa il file `.dmg` adatto al processore del Mac.

## Installazione su Windows

1. Apri la pagina [FishSTOP Latest](https://github.com/EugenioDeRosa/fishstop-desktop-email-security/releases/latest).
2. Scarica `FishStop_*_x64-setup.exe`.
3. Apri il file scaricato e segui la procedura guidata di installazione.
4. Al termine, avvia **FishStop** dal menu Start o dal collegamento creato dall'installer.

Se Microsoft Defender SmartScreen mostra un avviso, verifica che il file provenga dalla release ufficiale, quindi scegli **Ulteriori informazioni → Esegui comunque**.

> Non scaricare manualmente `fishstop-ollama-cuda.zip`: è un componente tecnico che FishStop gestisce automaticamente sui computer con una GPU NVIDIA compatibile.

## Prima configurazione: modello AI e chiavi API

Dopo l'installazione sono necessari due passaggi per attivare tutte le funzioni di protezione.

### 1. Installare il modello AI locale

1. Avvia FishStop ed effettua l'accesso con Google o Microsoft.
2. Apri **Settings** dal menu laterale.
3. Nella scheda **Machine and automatic model**, individua la sezione **FishStop AI → Local AI model**.
4. Seleziona **Install AI model**.
5. Mantieni FishStop aperto fino al completamento del download. La schermata mostra lo stato e l'avanzamento dell'installazione.
6. Quando compare il messaggio che il modello locale è installato e pronto, l'analisi semantica è attiva.

Non è necessario installare Python, Ollama o MLX: il runtime adatto alla piattaforma è già incluso nell'app. Su Apple Silicon viene usato MLX; sui Mac Intel e su Windows viene usato il runtime Ollama incluso. Il modello può essere rimosso in qualsiasi momento con **Remove model**.

### 2. Inserire le chiavi API di reputazione

Per abilitare tutti i controlli di reputazione prepara una chiave personale per ciascun servizio:

- **VirusTotal API key**, per URL, hash e domini;
- **AbuseIPDB API key**, per gli indirizzi IP pubblici della catena di recapito;
- **AlienVault OTX API key**, per le corrispondenze esatte con indicatori di threat intelligence.

Poi:

1. Apri **Settings → Reputation**.
2. Seleziona **Configure keys**. Se alcune chiavi sono già presenti, il pulsante diventa **Edit keys**.
3. Incolla le tre chiavi nei rispettivi campi.
4. Seleziona **Save changes**.
5. Controlla che ogni servizio mostri lo stato **Ready** e che l'indicatore superiore mostri **Protection active**.

Le chiavi vengono conservate nel portachiavi sicuro del sistema operativo e non sono salvate in chiaro nell'interfaccia. Se una chiave manca, FishStop continua a eseguire i controlli statici e l'AI locale, ma il relativo controllo di reputazione rimane non disponibile.

## Modello AI e accelerazione

FishStop seleziona automaticamente il backend e il modello adatti alla piattaforma; non è prevista una selezione manuale.

- **Apple Silicon:** MLX con `mlx-community/Qwen3-4B-Instruct-2507-4bit` e accelerazione Metal.
- **macOS Intel e Windows:** Ollama con `qwen3:4b-instruct-2507-q4_K_M`.
- **Windows con GPU NVIDIA:** il pacchetto CUDA viene scaricato una sola volta, verificato tramite SHA-256 e conservato nella cartella dati dell'app.
- **Windows con GPU AMD o Intel:** FishStop prova l'accelerazione Vulkan.
- **Sistemi senza accelerazione compatibile:** viene usata la CPU con un profilo ottimizzato e limiti dedicati.

Il modello viene caricato soltanto durante l'analisi e viene rilasciato al termine, anche in caso di errore o annullamento. Se l'AI non conclude entro il tempo previsto, i controlli statici restano comunque disponibili.

## Privacy e dati locali

Il corpo dell'email viene elaborato dal modello AI sul dispositivo. VirusTotal, AbuseIPDB e OTX ricevono soltanto gli indicatori tecnici necessari al controllo configurato; il contenuto del messaggio e il file `.eml` non vengono inviati.

L'accesso Google e Microsoft usa OAuth Authorization Code con PKCE e callback locale. FishStop non salva password. Quando l'utente collega volontariamente la casella, il refresh token necessario all'accesso in sola lettura viene custodito nel portachiavi di sistema e rimosso con **Disconnect**. Cronologia e preferenze restano sul dispositivo e sono separate per provider e account.

Per l'integrazione della casella, il progetto OAuth Google deve avere Gmail API e lo scope `gmail.readonly`; Microsoft Entra deve consentire la permission delegata `Mail.Read`. Google può richiedere la verifica della consent screen prima della distribuzione pubblica perché l'accesso a Gmail usa uno scope restricted.

## Avvio in sviluppo

Prerequisiti: Node.js LTS, Rust e Python 3.

```bash
npm install
python3 -m venv .venv
.venv/bin/pip install -r src-python/requirements.txt pyinstaller
npm run tauri dev
```

In modalità sviluppo FishStop esegue direttamente `src-python/main.py`, quindi le modifiche Python vengono applicate senza ricreare il sidecar.

### Backend MLX in sviluppo su Apple Silicon

Per provare MLX in sviluppo usa un ambiente Python separato:

```bash
python3 -m venv .venv-mlx
.venv-mlx/bin/pip install -r src-python/requirements-mlx.txt
npm run tauri:mlx
```

Dopo l'avvio, installa il modello dalla sezione **Settings → FishStop AI** come nella build distribuita.

## Creare una build installabile

Il pacchetto include il motore Python come sidecar e il runtime locale richiesto dalla piattaforma. Prima della build crea il sidecar per l'architettura corrente:

```bash
.venv/bin/pip install -r src-python/requirements.txt pyinstaller
FISHSTOP_TARGET_TRIPLE=$(rustc --print host-tuple) .venv/bin/python scripts/build_sidecar.py
npm run tauri build
```

Su Apple Silicon, la build distribuita prepara inoltre il sidecar MLX tramite `scripts/build_mlx_sidecar.py`. Per le altre piattaforme il workflow include il runtime Ollama tramite `scripts/download_ollama_runtime.py`. L'utente finale non deve installare Python né questi runtime manualmente.
