# FishSTOP Fast Lite v4 — cosa fare su Colab

Questo pacchetto prepara un candidato da confrontare con Fast v3. Non sostituisce
il modello installato e non dichiara un miglioramento prima delle prove reali.
Parti dal modello originale **Qwen3-1.7B**, non dal GGUF e non dall’adapter v3.

## Contenuto e obiettivo

Il dataset contiene **3.706 esempi sintetici**: 2.466 training, 620 validation,
620 test. Comprende il corpus v3 con prompt rigenerati dal codice dell’app e
864 nuovi esempi derivati da 24 coppie di scenari, in italiano e inglese.
Le aggiunte includono tre task: analisi principale, identità nella firma e
verifica indipendente del contenuto. Il materiale portoghese precedente resta.
Varianti e task della stessa ricetta restano nello stesso split.

L’output principale ora usa `verdict`, `quote`, `explanation` come l’app attuale.
Le spiegazioni ereditate riutilizzano i riepiloghi precedentemente annotati;
non sono state certificate da annotatori indipendenti. Cinquanta vecchi target
di verifica dell’identità sono stati corretti: mancava nell’input la prova di
mismatch che la risposta dichiarava. I riferimenti alle firme sono dichiarazioni
d’identità, mai prove di autenticità. Un QR non decodificato comporta incertezza:
questo modello testuale non decodifica le immagini.

Le 68 email già discusse, la newsletter e il caso VPN sono esclusi dal training.
Le nuove ricette affrontano categorie di errori conosciute: i test sintetici e il
benchmark storico non sono una valutazione cieca indipendente.

## 1. Prima sessione: training

1. Estrai `fishstop-fast-lite-v4-colab.zip` sul computer.
2. Apri Colab e carica **FishSTOP_Fast_Lite_v4_01_FineTune_Colab.ipynb**
   tramite **File → Carica notebook**. Seleziona una GPU dal menu Runtime.
3. Esegui la sezione 1 di installazione. Quando termina, **riavvia la sessione
   senza eliminarla**, poi prosegui dalla sezione 2. Non ripetere l’installazione
   dopo il riavvio. Se l’installazione fallisce, conserva il messaggio completo.
4. Alla sezione 3 lascia i parametri forniti. `USE_DRIVE=True` conserva il run
   sotto `MyDrive/FishSTOP/fast-lite-v4/<data-ora>/`. Autorizza il montaggio Drive.
   Con `USE_DRIVE=False`, eliminare la sessione può far perdere i risultati.
5. Alla sezione 4 carica **solo fishstop-fast-lite-dataset-v4.zip**, estratto dal
   pacchetto. Non caricare lo ZIP completo, un dataset precedente o un adapter.
6. Prosegui in ordine. La sezione 9 esegue l’addestramento e salva immediatamente
   l’adapter. Non rieseguire questa cella dopo un run terminato.
7. La sezione 10 esegue confronti su validation e test; lascia
   `RUN_GENERATION_TESTS=True` e `EVALUATE_HELPER_TASKS=True`. Il campione
   generativo comprende 160 esempi validation e 160 test, non tutte le varianti.
   La loss validation usa un campione stratificato di 64 esempi.
8. Alla sezione 11 scarica **fishstop_fast_lite_adapter_v4.zip**. Una copia resta
   anche nella cartella del run su Drive. Conserva questo file.

La baseline sul modello originale è disattivata di default per evitare un altro
giro generativo prima del training. Se vuoi anche il confronto base→v4, imposta
`RUN_BASELINE=True` prima di iniziare. Non è il confronto Fast v3→v4: quello lo
faremo dopo con Ollama e la stessa versione dell’app. Saltare baseline o test non
deve impedire il salvataggio; gli esiti saltati sono marcati `not_run`.

Parametri iniziali: una epoca, LoRA rank/alpha 16/32, learning rate 5e-5,
batch 1 con accumulo 16, massimo 3.072 token, 155 aggiornamenti previsti.
Nessun esempio viene troncato; la loss riguarda solo la risposta dell’assistente.
I checkpoint vengono salvati e valutati ogni 25 aggiornamenti. Il checkpoint
selezionato usa la loss validation; il test non viene usato per selezionarlo.
Non modificare subito questi valori per inseguire il risultato del test.

## Fermare e riprendere

Puoi interrompere la cella di training con il pulsante Stop di Colab. Non significa
che l’ultimo aggiornamento sia stato salvato: puoi riprendere dall’ultimo checkpoint
periodico completato su Drive, perdendo il lavoro successivo a quel checkpoint.

Per riprendere dopo una disconnessione:

1. Riapri il notebook in una sessione GPU e completa installazione/riavvio.
2. Nella sezione 3 imposta `RESUME_FROM_CHECKPOINT` al percorso completo, ad esempio
   `/content/drive/MyDrive/FishSTOP/fast-lite-v4/20261019-120000/checkpoints/checkpoint-25`.
   È un esempio: usa la cartella effettivamente presente nel tuo Drive.
3. Ricarica lo stesso dataset e lascia identici i parametri del run.
4. Esegui le celle nell’ordine previsto. Il notebook recupera la cartella originale
   e rifiuta checkpoint incompleti, dati o parametri differenti.

Se il training era già terminato, recupera l’adapter da Drive e passa alla
conversione. Se si interrompono solo le valutazioni, l’adapter è già salvo.
Scaricalo comunque e conserva gli errori, senza ripetere il training per questo.

## 2. Seconda sessione: conversione

1. Apri **FishSTOP_Fast_Lite_v4_02_Conversione_Q4_Colab.ipynb** in una **nuova
   sessione GPU**, con almeno 25 GB liberi.
2. Completa installazione e riavvio come nel primo notebook.
3. Alla sezione 3 carica **solo fishstop_fast_lite_adapter_v4.zip**, prodotto dal
   training. Non caricare il dataset o il pacchetto iniziale.
4. Esegui le celle in ordine. Download del modello originale, unione intermedia
   e quantizzazione Q4_K_M sono previsti. Training e conversione fissano la stessa
   revisione del modello base e conservano il template senza thinking.
5. Scarica **entrambi** i risultati:
   - `fishstop-fast-lite-v4-Q4_K_M.gguf`
   - `fishstop-fast-lite-v4-istruzioni.zip`

Il controllo della conversione verifica header, dimensione, checksum e template.
Non equivale a una prova di qualità del GGUF: la faremo con Ollama.

## 3. Cosa riportare per il confronto

Conserva e rendi disponibili nella cartella del progetto:

- GGUF Q4_K_M;
- ZIP delle istruzioni con Modelfile, export_report.json e report di confronto;
- ZIP adapter, con comparison.json, failed_cases.json e training_info.json;
- messaggi di errore eventuali e tipo di GPU usata.

In seguito confronteremo Fast v3 e v4 con gli stessi input, codice dell’app,
parametri e macchina. Conteremo separatamente phishing mancati, falsi allarmi,
casi da verificare, output invalidi, citazioni inventate e tempi. Le 68 email
saranno una regressione; servirà anche un nuovo campione reale non usato per
progettare gli esempi. Non cambiare le etichette del benchmark in base all’output
del candidato. Il contenuto grezzo del modello e il verdetto finale dell’app
vanno confrontati separatamente. Una risposta valida e ben citata può comunque
contenere un’interpretazione sbagliata: le spiegazioni richiedono revisione.

## Verifiche già eseguite e limiti

Controlli locali: schemi attuali, citazioni letterali, separazione delle ricette,
tokenizer originale e mascheramento su tutti i record, checksum, flusso dei due
notebook, salvataggio senza baseline/test, errori di valutazione, ripresa e layout
di esportazione. Le operazioni GPU vengono sostituite da simulazioni nei test.
**Non è stato eseguito un training GPU reale né una conversione GGUF reale per v4.**
Le versioni fissate delle principali librerie risultano disponibili su PyPI;
la compatibilità effettiva va confermata nella sessione Colab. Non è garantita
una durata: dipende da GPU assegnata, installazione, download, Drive e valutazioni.
Dataset, email, report e pesi restano fuori da Git.

Riferimenti tecnici: [TRL SFT](https://huggingface.co/docs/trl/sft_trainer),
[checkpoint Transformers](https://huggingface.co/docs/transformers/trainer_recipes),
[template e uso in Ollama](https://docs.unsloth.ai/basics/saving-and-using-models/troubleshooting),
[risorse Colab](https://research.google.com/colaboratory/faq.html).
