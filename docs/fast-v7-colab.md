# FAST Lite v7: training candidato contro i falsi positivi

Kit locale: `training/fishstop-fast-lite-v7-colab.zip`. Il contenuto completo resta fuori da Git, insieme a dataset, modelli, campioni email e report. Nessuna modifica al modello installato o alla pubblicazione HF.

Il corpus è ricostruito senza ereditare le etichette v3-v6: 36 famiglie, 288 testi bilingui prima delle varianti, 3744 record con task ausiliari. Split per famiglia: 2496 train, 624 validation, 624 test. Ogni famiglia comprende due casi ordinari, una frode esplicita e un caso da verificare. Le categorie degli errori noti hanno guidato il disegno; non è un test cieco né un dataset revisionato indipendentemente.

Contrasti principali: notifiche bancarie e contatto facoltativo; VPN/QR non ispezionati; attestati e firme già archiviati; newsletter e documenti; credenziali ricevute rispetto a segreti richiesti; codici nella propria app rispetto a codici consegnati a un operatore; pagamenti concordati e deviazioni; citazioni educative e ricatti reali. I dati mancanti non sono prova di frode. Le chiamate di verifica devono rispettare gli stessi vincoli dell'analisi primaria.

Allenamento dal Qwen3-1.7B originale a revisione fissata, una epoca, LoRA 16, learning rate 2e-5, contesto massimo 4096 e perdita soltanto sulle risposte. Non si prosegue dal GGUF o dall'adapter v6. Prompt e schema corrispondono all'app attuale. Non sono stati introdotti controlli applicativi basati su parole chiave.

## Uso

1. Estrarre il kit; aprire `FishSTOP_Fast_Lite_v7_01_FineTune_Colab.ipynb` in Colab con GPU e Drive.
2. Quando richiesto caricare solo `fishstop-fast-lite-dataset-v7.zip`. Lasciare attivi baseline e valutazioni ausiliarie.
3. Scaricare lo ZIP adapter; leggere `acceptance_gate.json`, risultati e `rationale_review.csv`.
4. In una nuova sessione GPU aprire `FishSTOP_Fast_Lite_v7_02_Conversione_Q4_Colab.ipynb`, caricare lo ZIP adapter e scaricare il GGUF Q4_K_M come candidato separato.

Baseline: 192 richieste al modello originale, non a Fast v4/v5/v6. Dopo il training: 192 richieste validation e 192 test. Il checkpoint è scelto con loss validation. Il gate rifiuta valutazioni incomplete, campi errati, citazioni inventate e regressioni rispetto alla baseline; non certifica le spiegazioni e non abilita pubblicazioni automatiche. Export disponibile anche per analizzare candidati bocciati.

Prima della promozione servono revisione umana e confronto nella stessa app: 24 casi della regressione v6, tutte le 68 email, poi email nuove. Distinguere giudizio AI ed esito delle regole; controllare falsi positivi, falsi negativi, review, motivazioni, chiamate e tempi ripetuti. L'obiettivo non è aumentare le classificazioni legittime a costo di perdere phishing.

La guida completa nel kit spiega ripresa da checkpoint, checksum, limiti, 12 stress test lunghi per l'intera pipeline e revisione dei 288 testi di base. Le verifiche locali coprono dati/tokenizer reali e flusso dei notebook con operazioni GPU simulate. Non sono training, inferenza v7 o conversione reale e non dimostrano miglioramenti. Il candidato non può essere dichiarato “definitivo” prima del confronto.
