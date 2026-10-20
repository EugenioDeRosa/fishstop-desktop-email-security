# FishSTOP FAST Lite v5 — istruzioni Colab

Questo è un **candidato da confrontare con FAST v4**. Non sostituisce il modello
dell'app. Non è stato ancora allenato su GPU e non è dimostrato che migliori i
verdetti. I controlli locali verificano dati, contratti e notebook, con simulazioni
al posto delle operazioni GPU.

## Cosa cambia

- 4.546 record sintetici: **2.970 train, 788 validation, 788 test**.
- Conserva i 3.706 record v4, rigenera i prompt dall'app attuale e migliora 2.092
  citazioni ereditate usando frasi dell'azione già annotata. Questo intervento
  meccanico non certifica la correttezza semantica delle vecchie spiegazioni.
- Aggiunge **840 record**: 360 analisi principali, 360 verifiche indipendenti e
  120 estrazioni dell'identità. Derivano da 20 ricette con tre casi ciascuna:
  lecito, phishing, incerto; due lingue e tre presentazioni. Varianti e task non
  sono esempi indipendenti. Le etichette sono autoriali, non una doppia annotazione.
- Rafforza il collegamento fra fatti e meccanismo della truffa, le differenze fra
  consegna e raccolta di credenziali, i flussi documentali e i limiti delle prove.
  Password, importo, dominio sconosciuto o firma non determinano da soli il rischio.
- I casi da verificare restano tali: un QR non decodificato non diventa sicuro,
  e questo modello testuale non impara a leggere le immagini.
- Ogni nuova ricetta resta in un solo split: 12 train, 4 validation, 4 test,
  con tutte le traduzioni, classi, presentazioni e task. Gli split precedenti
  sono conservati. Il test non sceglie il checkpoint.

Le 68 email, il caso VPN e la newsletter discussa sono esclusi. Sono state
controllate sovrapposizioni testuali con le loro viste e con le valutazioni
sintetiche precedenti. La progettazione conosce però le categorie degli errori:
non rivendichiamo indipendenza concettuale o un test reale cieco. Nessuna email
privata è contenuta nel pacchetto.

## 1. Estrai il pacchetto

Estrai `fishstop-fast-lite-v5-colab.zip`. Troverai due notebook, il dataset ZIP,
questa guida e i controlli di integrità. Non devi caricare lo ZIP completo in
una cella: ciascun notebook chiede un file specifico.

## 2. Prima sessione: training

1. Apri Google Colab e scegli **File → Carica notebook**.
2. Seleziona `FishSTOP_Fast_Lite_v5_01_FineTune_Colab.ipynb` e attiva una GPU
   da **Runtime → Cambia tipo di runtime**.
3. Esegui la sezione 1. Al termine **riavvia la sessione senza eliminarla**,
   poi prosegui dalla sezione 2. Non ripetere l'installazione dopo il riavvio.
4. Lascia i parametri della sezione 3. `USE_DRIVE=True` salva il run in
   `MyDrive/FishSTOP/fast-lite-v5/<data-ora-UTC>/`: autorizza il montaggio Drive.
5. Alla sezione 4 carica **solo `fishstop-fast-lite-dataset-v5.zip`**.
   Non caricare il kit completo, un adapter o il GGUF v4.
6. Prosegui nell'ordine. Il notebook parte dal modello originale Qwen3-1.7B
   con revisione fissata e crea un nuovo adapter. Non prosegue l'adapter v4 e
   non addestra un GGUF.
7. La sezione 9 allena e salva immediatamente l'adapter su Drive, prima dei test.
   Non rieseguire questa cella dopo un training concluso.
8. La sezione 10 valuta campioni deterministici di **232 record validation e
   232 test**, inclusi identità e verificatori. Lascia `RUN_GENERATION_TESTS=True`
   ed `EVALUATE_HELPER_TASKS=True`.
9. Alla sezione 11 scarica **`fishstop_fast_lite_adapter_v5.zip`** e conservalo.

Ricetta: **una epoca**, LoRA rank/alpha 16/32, learning rate 5e-5, batch 1 con
accumulo 16, massimo 3.072 token, **186 aggiornamenti** previsti. Nessun esempio
viene troncato; vengono allenati solo i token della risposta. Ogni 25 aggiornamenti
salva un checkpoint e valuta la loss su 128 record validation selezionati per task
e classe. Mantiene i checkpoint necessari e carica quello scelto dalla loss.

La baseline sul modello originale è **disattivata di default**. Puoi attivare
`RUN_BASELINE=True` prima del training, ma quel confronto sarà base originale →
v5, **non FAST v4 → v5**. Non serve eseguirlo per salvare l'adapter. Tempi e
compatibilità effettiva dipendono dalla GPU e dalla sessione Colab; non è garantita
una durata. I test generativi aggiungono tempo al training.

## 3. Interrompere e riprendere

**Durante il training:** puoi usare Stop di Colab. L'ultimo aggiornamento può
andare perso: si riprende dall'ultimo checkpoint completo, non dal punto esatto
dello Stop. Con Drive disattivato, eliminare la sessione può cancellare il lavoro.

Per riprendere in una nuova sessione GPU:

1. Riapri il notebook, completa installazione e riavvio.
2. Nella sezione 3 imposta `RESUME_FROM_CHECKPOINT` al percorso effettivo, ad esempio
   `/content/drive/MyDrive/FishSTOP/fast-lite-v5/20261020-100000/checkpoints/checkpoint-25`.
3. Ricarica lo stesso dataset e mantieni identici parametri, seed e campione della
   loss validation. Il notebook recupera la cartella originale e verifica contratto,
   adapter, stato trainer, optimizer, scheduler e stato casuale.
4. Prosegui nell'ordine. Se il training era già completo, recupera invece l'adapter
   da Drive e passa alla conversione: non serve ripetere l'allenamento.

**Durante i test finali:** ogni risposta è salvata in `evaluations/` nella cartella
del run. Nella stessa sessione riesegui **solo la sezione 10**: riutilizza i casi
completati e riprova l'eventuale generazione interrotta. Cache, dataset, pesi e
campione devono coincidere. JSON o citazioni sbagliati restano errori e non vengono
ritentati per scegliere una risposta più favorevole. Se riavvii completamente la
sessione, puoi comunque recuperare l'adapter già salvato e convertirlo; la ripresa
dei test generativi richiede anche il modello allenato nuovamente caricato in memoria.

Controlla `coverage.complete`: un test parziale non è un confronto completo.
Puoi scaricare l'adapter dalla sezione 11 anche dopo un errore di valutazione.
I report riportano ciò che è stato eseguito, gli errori e le fasi saltate.

## 4. Seconda sessione: conversione Q4_K_M

1. Apri `FishSTOP_Fast_Lite_v5_02_Conversione_Q4_Colab.ipynb` in una **nuova
   sessione GPU**, con almeno 25 GB liberi.
2. Completa installazione e riavvio come sopra.
3. Alla sezione 3 carica **solo `fishstop_fast_lite_adapter_v5.zip`**.
   Sono controllati versione, checksum, base e dataset del kit v5.
4. Esegui in ordine unione e conversione. Il notebook considera anche la cartella
   sorella `_gguf`, mantiene il template Qwen3 senza thinking e prepara il Modelfile.
5. Scarica **entrambi**:
   - `fishstop-fast-lite-v5-Q4_K_M.gguf`;
   - `fishstop-fast-lite-v5-istruzioni.zip`.

Il controllo di header, dimensione, template e checksum non equivale a un test di
qualità del GGUF. Mantieni anche lo ZIP adapter per non ripetere il training se
si interrompe solo la conversione.

## 5. Materiale da riportare e criteri di confronto

Conserva **GGUF, istruzioni ZIP e adapter ZIP**. Includono metadati di training,
versioni, checksum, confronto, casi falliti e **`rationale_review.csv`**.

Il CSV affianca testo, risposta attesa, risposta prodotta e dettagli che non vanno
inventati. I campi di revisione umana sono vuoti: verifica se la spiegazione
descrive un meccanismo supportato, se inventa fatti e se l'incertezza è motivata.
Non viene assegnato automaticamente un voto alla qualità semantica delle spiegazioni.

Le metriche separano phishing mostrati leciti, falsi allarmi, revisioni, output
invalidi e comportamento del verificatore. Un `basis=contextual_deception` corretto
come etichetta non certifica la verità della spiegazione.

Prima di promuovere v5 confronteremo **v4 e v5 con la stessa app e il parser
aggiornato**, stessi parametri e hardware, su tutte le 68 email e su un nuovo
campione reale autorizzato non usato per progettare i dati. Quel nuovo campione
reale non è incluso in questo kit. Il protocollo è descritto anche in
`CONFRONTO_V4_V5.md`; questo pacchetto non ha già eseguito quel benchmark.

Riferimenti tecnici:
[TRL SFT](https://huggingface.co/docs/trl/sft_trainer),
[compatibilità template Unsloth/Ollama](https://docs.unsloth.ai/basics/saving-and-using-models/troubleshooting).
