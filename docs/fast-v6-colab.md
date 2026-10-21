# Fast Lite v6: candidato di fine tuning

Il kit locale del 21 ottobre 2026 si trova in `training/fishstop-fast-lite-v6-colab.zip`.
Contiene due notebook Colab, dataset sintetico, guida e controlli. Gli artefatti
generati restano esclusi da Git. Non è un modello già allenato.

Il corpus parte da Fast Lite v5 e aggiunge 24 ricette con casi malevoli, legittimi e
incerti su OTP, seed, pagamenti, accesso remoto, allegati e notifiche. Tutte le
varianti della stessa ricetta restano nello stesso split. Sono usati schema e
prompt attuali, citazioni letterali, verifica indipendente e risposte senza
summary o campi facoltativi neutri superflui. La valutazione conta comunque
eventuali flag inventati. Le email private già testate non entrano nel training.

Aprire `FishSTOP_Fast_Lite_v6_01_FineTune_Colab.ipynb` in Colab con GPU, eseguire le
celle e caricare il solo ZIP dataset incluso. Si parte da Qwen3-1.7B originale,
con revisione fissata, una epoca QLoRA, rank 16, learning rate 3e-5 e limite di
4096 token senza troncamento. Drive conserva checkpoint e adapter.
Il notebook `02` converte lo ZIP adapter in GGUF Q4_K_M in una nuova sessione GPU.
Seguire la guida completa inclusa nel kit per riprendere un run interrotto.

La baseline opzionale è Qwen3 originale; Fast v4 distribuito richiede un confronto
successivo nella stessa applicazione. Fast v5 non aveva dimostrato un vantaggio
complessivo: non assumere che la numerazione nuova garantisca maggiore qualità.
Controllare falsi negativi, falsi positivi, review, spiegazioni, numero di chiamate
e tempi, poi valutare email nuove. Non sostituire automaticamente il modello in uso.

I controlli locali usano il tokenizer reale e simulano le librerie GPU per
verificare il flusso dei notebook. Nessun training GPU, conversione reale o
miglioramento di accuratezza è stato dimostrato. Parser e regole dell'app restano
interventi separati; il training non recupera testo mancante dall'input.
