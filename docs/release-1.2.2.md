# FishSTOP 1.2.2

- FAST passa a Lite v4 Q4_K_M. Il download viene verificato per nome, dimensione
  e SHA-256. La modalità FAST scelta con versioni precedenti viene conservata;
  il vecchio modello non viene scambiato per un'installazione della v4.
- Le valutazioni AI supportate dal contenuto hanno maggiore peso nel verdetto.
  Citazioni, interpretazione della richiesta e motivazione vengono validate;
  evidenze incomplete possono richiedere una verifica.
- Il controllo d'identità considera la firma del messaggio selezionato e tratta
  separatamente autenticazione disponibile, verifica indipendente e riferimenti
  aziendali. Una verifica SPF non eseguita non è un fallimento SPF.
- Un Reply-To diverso dal From richiede contesto: la differenza da sola non
  dimostra un furto di credenziali, anche nei flussi di condivisione documenti.
- I link di newsletter non diventano richieste di verifica account solo perché
  il testo contiene parole generiche come account o sicurezza.
- Il parser compatta blocchi ripetuti e sovrapposizioni tra testo e HTML,
  mantenendo differenze, richieste, link e firma per l'identità. Le annotazioni
  del parser non possono diventare citazioni originali dell'email.
- Le etichette italiane dei dettagli e del modello sono più concise.

La pubblicazione degli installer richiede che FAST v4 sia disponibile su Hugging
Face e superi `scripts/verify_fast_release_model.mjs`. Dataset, email, adapter,
pesi e report di valutazione locali non fanno parte dei sorgenti dell'app.
