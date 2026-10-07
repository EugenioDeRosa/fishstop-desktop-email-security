# FishStop

FishStop è un'app desktop per macOS e Windows che analizza email sospette in formato `.eml`. Combina controlli tecnici, reputazione degli indicatori e analisi semantica locale per riconoscere phishing, truffe e Business Email Compromise senza inviare il contenuto dell'email a servizi AI esterni.

Versione attuale: **1.0.0**.

## Funzionalità principali

- Analisi di header, catena di recapito, SPF, DKIM, DMARC, `Reply-To` e `Return-Path`.
- Rilevamento di domini lookalike, URL mascherati, redirect, download rischiosi e incongruenze tra la richiesta e la risorsa proposta.
- Ispezione sicura di HTML e allegati, senza eseguire script, form o contenuti remoti.
- Analisi locale dell'identità dichiarata e dell'intento del messaggio tramite un modello Qwen gestito automaticamente da FishStop.
- Riconoscimento delle conversazioni incorporate nelle email inoltrate o nelle risposte: prima dell'analisi è possibile scegliere quali messaggi valutare e quali includere soltanto come contesto.
- Controlli di reputazione con VirusTotal, AbuseIPDB e AlienVault OTX, con Spamhaus ZEN come fallback per gli IP quando AbuseIPDB non è configurato. Ai servizi esterni vengono inviati esclusivamente indicatori tecnici compatibili con ciascun servizio, mai il file `.eml` o il testo dell'email.
- Importazione di un file `.eml` tramite selezione o trascinamento, fino a 40 MB.
- Collegamento facoltativo e in sola lettura della casella Gmail o Outlook associata all'accesso. FishStop mostra gli ultimi 10 messaggi e scarica il MIME/EML completo solo quando si avvia l'analisi.
- Cronologia locale, statistiche per periodo, report tecnico consultabile ed esportazione JSON.

## Report JSON per SIEM

Il pulsante **Download JSON** nella scheda tecnica esporta un evento di sicurezza compatto, pensato per l'ingestione in SIEM, data lake e pipeline SOC. Il formato non replica lo stato interno dell'interfaccia: espone soltanto dati operativi e usa un contratto versionato tramite `schema_version`.

Le sezioni principali sono:

- `event`: identificativo, categoria, prodotto e data di esportazione;
- `email`: metadati RFC essenziali e hash SHA-256 del file EML;
- `verdict`: classificazione, severità, punteggio di rischio, confidence e motivazione;
- `authentication`: risultati normalizzati SPF, DKIM e DMARC e anomalie di allineamento;
- `network`: IP sorgente e percorso SMTP in ordine cronologico, senza header grezzi;
- `indicators`: URL, domini, IP e hash deduplicati, con contesto e reputazione disponibile;
- `attachments`: nome, tipo, dimensione, hash, rischio e anomalie degli allegati;
- `findings`: evidenze normalizzate con ID, categoria e severità;
- `content`: sintesi semantica e azione richiesta, senza esportare il corpo completo;
- `analysis`: stato e metadati essenziali dei motori di analisi.

Lo schema FishStop è intenzionalmente indipendente dal fornitore, ma i nomi e i tipi sono facilmente mappabili verso Elastic Common Schema, Splunk CIM e Microsoft Sentinel. I campi senza valore, gli oggetti vuoti e gli array vuoti vengono omessi. Non vengono esportati il corpo integrale, l'HTML, l'anteprima EML, gli header grezzi, prompt o output interni del modello, coordinate geografiche e dati usati soltanto dalla UI.

Esempio ridotto:

```json
{
  "schema_version": "1.0",
  "event": {
    "kind": "alert",
    "category": ["email", "threat"],
    "provider": "FishStop"
  },
  "email": {
    "message_id": "<example@example.com>",
    "subject": "Invoice overdue",
    "from": {
      "address": "billing@example.com",
      "domain": "example.com"
    },
    "eml_sha256": "..."
  },
  "verdict": {
    "classification": "suspicious",
    "severity": "medium",
    "risk_score": 55,
    "reason": "The message requests payment through an unverified link."
  },
  "indicators": [
    {
      "type": "url",
      "value": "https://example.net/login",
      "risk": "suspicious",
      "source": "message_body"
    }
  ]
}
```

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

Se macOS blocca il primo avvio perché non riconosce lo sviluppatore, apri **Impostazioni di Sistema → Privacy e sicurezza**, individua il messaggio relativo a FishStop e scegli **Apri comunque**.

Se **Apri comunque** non compare o l'app continua a non avviarsi:

1. Verifica che **FishStop.app** sia nella cartella **Applicazioni**.
2. Apri **Terminale** da **Applicazioni → Utility**.
3. Esegui questo comando:

   ```bash
   sudo xattr -dr com.apple.quarantine "/Applications/FishStop.app"
   ```

4. Inserisci la password del Mac quando richiesta e premi **Invio**. Durante la digitazione la password non viene mostrata nel Terminale.
5. Avvia nuovamente FishStop da **Applicazioni** oppure esegui:

   ```bash
   open "/Applications/FishStop.app"
   ```

Il percorso `/Applications/FishStop.app` è valido per tutti gli utenti quando l'app è stata spostata nella cartella **Applicazioni** come indicato sopra. Rimuovi l'attributo di quarantena soltanto se hai scaricato FishStop dalla release ufficiale.

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
4. Seleziona **Install FishSTOP AI v5**.
5. Mantieni FishStop aperto fino al completamento del download. La schermata mostra lo stato e l'avanzamento dell'installazione.
6. Quando compare il messaggio che il modello locale è installato e pronto, l'analisi semantica è attiva.

Non è necessario installare Python, Ollama o MLX: il runtime adatto alla piattaforma è già incluso nell'app. Su Windows e macOS, anche Apple Silicon, il runtime Ollama incluso usa lo stesso modello FishSTOP AI v5. MLX resta un backend sperimentale esplicitamente attivabile con un export fine-tuned dedicato. Il modello può essere rimosso in qualsiasi momento con **Remove model**.

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

### FishSTOP AI v5: modello di riferimento

L'app usa il nostro Qwen3 4B fine-tuned v5 come modello AI predefinito e non
mostra più il toggle per passare a Qwen standard. Il tag selezionato è
`fishstop-qwen3:4b-finetuned-v5-q4_K_M`; le vecchie preferenze non lo disattivano.
Se il modello non si avvia, l'app segnala l'errore invece di sostituirlo
silenziosamente con un altro modello.

In **Settings → Machine and automatic model**, **Install FishSTOP AI v5**
scarica il modello completo quantizzato Q4_K_M (circa 2,5 GB), verifica dimensione
e SHA-256, lo importa nel runtime locale e ne verifica il caricamento.
Il download usa quattro connessioni in parallelo con parti da 16 MiB, mostra
l'avanzamento e riprende le parti completate dopo un'interruzione. Ogni parte
fallita viene ritentata fino a tre volte. Per server senza supporto HTTP Range
si usa un singolo trasferimento. Un file completo già verificato viene
riutilizzato dopo un errore di importazione.
Dopo l'installazione il modello funziona offline. **Remove** rimuove il tag v5
selezionato senza eliminare altri modelli dell'utente.

Il catalogo di distribuzione è `src-tauri/model-catalog.json` e contiene già il
link pubblico al [modello v5 su Hugging Face](https://huggingface.co/fishstop/fishstop-AI),
fissato alla revisione `b12b12895c0e812eeace23452195d2aacf13de80`.
Dimensione e checksum attesi sono registrati nel catalogo e verificati dall'app.

Il file distribuito è `fishstop-qwen3-v5-Q4_K_M.gguf`, il modello completo.
Non aggiungere pesi o token di accesso al Git del codice. Gli installer includono
il runtime; i pesi vengono scaricati solo su richiesta dell'utente.

Per lo sviluppo MLX esplicito su Apple Silicon, è necessario un modello
fine-tuned MLX completo sotto
`mlx-models/qwen3-4b-instruct-2507-finetuned-4bit` nella cartella dati dell'app.
L'app non installa più il modello MLX standard come alternativa al v5.

## Privacy e dati locali

### Controllo locale degli allegati Office

FishStop usa `oletools` per analizzare VBA, macro Excel 4/XLM e istruzioni DDE
negli allegati Office legacy, OOXML e RTF (per RTF viene controllato DDE).
Il controllo è automatico durante l'analisi statica: non serve una spunta e non
modifica il modello Qwen o il suo adapter. Le evidenze compaiono negli allegati,
nei flag, nel contesto AI e nei report JSON/SIEM. La sola presenza di VBA è
informativa; avvio automatico, comportamenti sospetti e DDE richiedono revisione.
Non è un antivirus e non dimostra che un file sia innocuo o malevolo.

I documenti sono analizzati in un processo separato, senza aprire Office,
eseguire macro o emulare XLM. Nessun documento viene caricato online da questo
controllo; gli URL estratti possono entrare nei controlli di reputazione già
configurati. Il codice VBA completo non viene inviato al modello.
Il limite è 8 secondi per documento e 20 secondi/5 documenti per email,
con limite di 10 MiB per documento e limiti di decompressione OOXML.
Cifratura, formato non supportato, errori o limiti raggiunti producono un
controllo incompleto, mai un risultato pulito. Le macro XLM OOXML vengono
rilevate come fogli macro, senza deoffuscare le formule; gli oggetti incorporati
RTF e gli exploit binari non sono coperti da questo controllo.

La dipendenza è inclusa in `src-python/requirements.txt` e nella build del
sidecar. In sviluppo, dopo aver aggiornato le dipendenze, riavvia FishStop e
rianalizza le email: i report già salvati non vengono modificati retroattivamente.

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

### Avvio in sviluppo su Windows

Installa anche gli strumenti MSVC x64/x86 e Windows SDK dal carico di lavoro **Sviluppo di applicazioni desktop con C++** di Visual Studio Installer. Windows Performance Toolkit non è necessario.

Nel terminale PowerShell della cartella del progetto:

```powershell
npm.cmd install
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r src-python/requirements.txt pyinstaller
$env:FISHSTOP_TARGET_TRIPLE = 'x86_64-pc-windows-msvc'
.\.venv\Scripts\python.exe scripts/build_sidecar.py
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
npm.cmd run tauri -- dev
```

Il sidecar deve essere presente anche per la compilazione in sviluppo perché è dichiarato nella configurazione Tauri. Se compare l'errore `resource path binaries\fishstop-engine-x86_64-pc-windows-msvc.exe doesn't exist`, esegui il passaggio `build_sidecar.py`. Durante l'uso in sviluppo il motore continua a eseguire i sorgenti Python.

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
