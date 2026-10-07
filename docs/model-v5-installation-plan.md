# Installazione di FishSTOP AI v5 con un clic

Piano del 7 ottobre 2026. L'installazione descritta qui è da implementare;
il pulsante attuale installa ancora Qwen standard.

## Esperienza proposta

Al primo avvio, Settings → Machine and automatic model mostra:

- **FishSTOP AI v5**
- «Modello locale specializzato per l'analisi delle email. Download: circa 2,5 GB.»
- **Install FishSTOP AI**

Il clic scarica il modello, ne verifica l'integrità, lo registra nel runtime
incluso nell'app, esegue una breve verifica locale e lo attiva. Nessuna
installazione manuale di Ollama o selezione di file è richiesta all'utente.
Il download comincia soltanto con il clic; gli avvii successivi usano il modello
già installato, anche offline.

Gli stati visibili sono: Downloading → Verifying → Preparing → Ready.
Durante il download mostrare percentuale e byte scaricati. In caso di errore,
mostrare una causa comprensibile e **Retry**; mantenere l'eventuale modello già
funzionante. Un modello standard già presente non deve nascondere il pulsante
di installazione del v5.

## Situazione attuale e artefatto

Il backend ha già disponibilità, preferenza, identificazione della versione
tramite digest e ripiego sul modello standard per i fine-tune installati.
`install_default_model` in `src-tauri/src/ollama_runtime.rs` esegue però
`/api/pull` per Qwen standard. La UI di `src/main.ts` nasconde Install quando
il modello selezionato è pronto; oggi non offre il download del v5.

Il report locale di esportazione del v5 riporta:

| Campo | Valore |
| --- | --- |
| Artefatto | `fishstop-qwen3-v5-Q4_K_M.gguf` |
| Tipo | Modello completo, base e LoRA uniti, quantizzato Q4_K_M |
| Dimensione | 2.497.280.448 byte, circa 2,50 GB / 2,33 GiB |
| SHA-256 | `bbb685dd1c8694d865b831c6874e54ba6a7b0ed0652f13ed55432ea8253a059e` |
| Tag immutabile | `fishstop-qwen3:4b-finetuned-v5-q4_K_M` |
| Alias usato dall'app | `fishstop-qwen3:4b-finetuned-q4_K_M` |

Questi valori provengono da `training/fishstop-v5/export/export_report.json`
e `SHA256SUMS.txt`; prima della distribuzione va verificato nuovamente il
file GGUF effettivo. Il GGUF non si trova nella cartella export: la nota locale
di integrazione lo colloca in Downloads. I pesi non vanno aggiunti al Git
del codice né incorporati nell'installer desktop.

## 1. Distribuzione del modello

Scelta proposta: repository di modello Hugging Face, con revisione immutabile
e download HTTPS diretto del GGUF. Definire il repository effettivo prima
dell'implementazione del download; nessun URL pubblico del v5 è stato verificato
in questa attività. Pubblicare pesi, informazioni di provenienza, licenza e
limitazioni, verificando prima le condizioni di distribuzione del modello base.

Il file supera il limite di 2 GiB per singolo asset delle GitHub Releases.
Inoltre il workflow desktop elimina le release rolling precedenti: i pesi
devono avere un ciclo di pubblicazione indipendente dagli installer.

Aggiungere al codice un catalogo versionato, ad esempio
`src-tauri/model-catalog.json`, con versione, backend, URL immutabile,
dimensione, SHA-256, tag e parametri di importazione. Il catalogo iniziale è
incluso nell'app: non risolvere i pesi tramite un riferimento mobile `latest`.
Una nuova versione deve corrispondere a un nuovo artefatto e checksum.

Fonti: [limiti GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases),
[storage Hugging Face](https://huggingface.co/docs/hub/storage-limits).

## 2. Download e registrazione su Windows e macOS Intel

Estendere il percorso di installazione esistente mantenendo il runtime gestito
dall'app come destinazione del nuovo modello.

1. Verificare spazio libero, runtime e presenza del v5 esatto. Prevedere spazio
   per download temporaneo e importazione, circa 6 GB inizialmente, da misurare
   nel test reale; non scaricare nuovamente un artefatto verificato.
2. Scaricare in un file temporaneo sotto la cartella dati dell'app, aggiornando
   l'evento di avanzamento esistente con una fase esplicita. Usare streaming:
   mai caricare 2,5 GB interamente in memoria.
3. Gestire annullamento, interruzione e ripresa. Riprendere solo se il server
   supporta Range e l'artefatto coincide; altrimenti ripartire correttamente.
   Un file parziale non deve risultare installato.
4. Controllare dimensione e SHA-256 prima dell'importazione.
5. Registrare il GGUF tramite upload del blob a `/api/blobs/:digest` e creazione
   con `/api/create`, usando il template e i token stop del Modelfile v5.
   Preservare i limiti di contesto CPU già applicati dalle richieste dell'app.
6. Creare prima il tag v5 immutabile. Verificarne caricamento e risposta JSON
   locale con i prompt/schema dell'app; un test di caricamento non certifica
   la qualità dei verdetti.
7. Solo dopo il successo aggiornare l'alias stabile e salvare la preferenza
   fine-tuned. Conservare versione e digest installati; se il v5 è già attivo
   sull'Ollama esterno, riconoscerlo senza duplicazioni inutili.
8. Ripulire il download temporaneo dopo un'importazione riuscita. Su errore
   conservare lo stato precedente e consentire un nuovo tentativo.

Fonte API: [Ollama: blob e creazione di modelli](https://github.com/ollama/ollama/blob/main/docs/api.md).

## 3. Settings, stato e rimozione

- Distinguere modello disponibile da installare, modello installato e modello
  attivo. Esporre esplicitamente versione e fase di installazione nello stato.
- Riutilizzare la barra e l'evento `ollama-model-progress`, evitando download
  duplicati e mantenendo l'operazione visibile cambiando pagina.
- A fine installazione aggiornare/invalidate le cache di runtime e protezione,
  così Settings e dashboard riconoscono subito il v5 attivo.
- Conservare la scelta del modello standard nelle impostazioni avanzate per
  gli utenti che lo hanno installato. Il ripiego automatico è possibile solo
  se lo standard è effettivamente disponibile; non scaricare un secondo modello
  senza renderlo esplicito. Se nessun modello si avvia, segnalare AI non disponibile
  e mantenere i controlli statici, senza presentare un'analisi AI completata.
- Correggere **Remove**: oggi `remove_default_model` elimina il modello standard
  consigliato anche quando è attivo il fine-tuned. La rimozione deve indicare e
  gestire il modello selezionato, alias, tag gestiti e preferenza, senza eliminare
  altre versioni o modelli esterni dell'utente.
- Per gli utenti esistenti proporre l'installazione del v5 e rispettare la loro
  scelta; niente sostituzione silenziosa dei pesi al primo avvio aggiornato.

## 4. Apple Silicon

Il percorso Apple Silicon usa MLX: il GGUF Ollama non è l'artefatto nativo MLX
già atteso dall'app. Prima di offrire lo stesso clic su Mac M-series, produrre
e verificare un export v5 completo in MLX 4-bit con config, tokenizer e pesi,
derivato dallo stesso fine-tune, e pubblicare un manifest con checksum per file.
La cartella attualmente prevista è
`mlx-models/qwen3-4b-instruct-2507-finetuned-4bit` nella cartella dati dell'app.

Prima milestone: installer GGUF per Windows/macOS Intel. Fino alla disponibilità
dell'export MLX verificato, Apple Silicon continua a installare Qwen MLX standard
con una descrizione coerente, senza dichiarare disponibile FishSTOP v5.

## 5. Verifica prima di renderlo il modello consigliato

La nota locale di integrazione del v5 registra ancora un falso positivo sulla
notifica OTP lecita e un errore di canale OAuth. Il download funzionante non
dimostra che il v5 migliori il verdetto completo. Prima della distribuzione
come modello consigliato, confrontare v5 e standard con gli stessi prompt,
schema, quantizzazione e opzioni, usando sia regressioni note sia un campione
indipendente di email legittime e sospette.

Verificare inoltre:

- Prima installazione su profilo pulito, senza Ollama esterno; attivazione e
  nuova analisi offline dopo riavvio dell'app.
- Modello standard già presente; v5 già presente; versione precedente presente.
- Rete interrotta, checksum errato, spazio insufficiente, clic ripetuti,
  annullamento e nuovo tentativo; nessuna attivazione di file incompleti.
- Caricamento fallito e recupero dello stato precedente; rimozione e reinstallazione.
- Avanzamento coerente fino a Ready, anche cambiando pagina.
- Carico CPU/GPU e RAM con l'effettivo runtime incluso negli installer.
- Export MLX separato su Apple Silicon prima di abilitare il v5 su quella piattaforma.

## Ordine di lavoro

1. Validare il GGUF v5, la licenza e il confronto qualitativo; pubblicare
   l'artefatto su hosting stabile e fissarne URL/revisione.
2. Implementare catalogo, download verificato e registrazione nel runtime gestito.
3. Aggiornare Install/Remove, stato e cache in Settings; verificare su macchina pulita.
4. Distribuire il nuovo installer Windows/macOS Intel.
5. Preparare e validare l'export MLX v5 e abilitare lo stesso flusso su Apple Silicon.
