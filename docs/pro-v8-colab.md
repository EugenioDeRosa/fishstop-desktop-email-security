# Pro v8: candidato di fine tuning

Il kit locale del 21 ottobre 2026 si trova in `training/fishstop-performance-v8-colab.zip`.
Contiene due notebook Colab, dataset sintetico, guida e controlli di integrità. Dataset,
notebook generati, report e modelli restano locali ed esclusi da Git.

Il primo notebook parte da `unsloth/Qwen3-4B-Instruct-2507` originale, con revisione
fissata nel manifest; il secondo converte il nuovo adapter in GGUF Q4_K_M. Non usare
un GGUF come input di training e non sovrapporre automaticamente vecchi adapter.

Il corpus eredita Pro v7 e aggiunge 24 ricette con versioni malevole, legittime e
incerte. I casi coprono autenticazione, wallet, pagamenti, assistenza remota,
documenti e notifiche. Ricette, traduzioni e attività ausiliarie restano nello
stesso split. I vecchi output sono migrati a `verdict`, `quote`, `explanation`;
il vecchio summary e i campi opzionali neutri non vengono generati come target primario.
La valutazione verifica comunque i flag facoltativi inventati.

Si usa una epoca QLoRA, rank 16, learning rate 3e-5 e limite di 4096 token senza
troncamento. La memoria GPU effettiva deve essere misurata; per Pro è preferibile
una GPU con almeno 24 GB. Il contesto dell'applicazione non viene modificato.

Aprire il notebook `01`, selezionare GPU, eseguire le celle in ordine e caricare lo
ZIP dataset quando richiesto. Drive conserva checkpoint e adapter. Il notebook
`02` riceve lo ZIP adapter prodotto dal primo. Leggere `GUIDA_COLAB.md` nel kit
prima di iniziare; descrive ripresa, baseline opzionale e conversione.

Il checkpoint viene scelto sulla loss validation, mai sul test. La baseline
opzionale è il modello originale, non Pro distribuito. Verificare la copertura
delle valutazioni e rivedere le spiegazioni nel CSV prodotto. Successivamente
confrontare il GGUF con il modello distribuito nella stessa applicazione,
includendo tempi, chiamate, falsi negativi, falsi positivi e casi da verificare.

I controlli locali verificano dati, tokenizer, masking delle istruzioni, schemi,
salvataggi, ripresa e flusso di conversione con sostituti delle librerie GPU.
Non dimostrano compatibilità GPU, qualità del candidato o conversione reale.
Non è stato eseguito un allenamento. Le annotazioni sintetiche non sono state
revisionate indipendentemente; le spiegazioni ereditate richiedono controllo.
I vecchi audit che affermavano un inganno d'identità senza osservazione
indipendente sono corretti esplicitamente nella migrazione.

Le email reali già esaminate rimangono escluse dal training e possono servire per
regressione; occorre anche un test nuovo. Testo perso nel parsing, destinazioni
omesse dall'input ed errori delle regole applicative richiedono interventi separati.

Riferimenti: [Qwen3 con Unsloth](https://github.com/QwenLM/Qwen3/blob/main/docs/source/training/unsloth.md),
[TRL SFTTrainer 0.22.2](https://huggingface.co/docs/trl/v0.22.2/en/sft_trainer).
