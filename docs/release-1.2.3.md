# FishSTOP 1.2.3

- FAST passa a Lite v7.1 Q4_K_M. Il download viene verificato per nome,
  dimensione e SHA-256. Nel confronto locale su 100 email, 68 di regressione e
  32 nuove, la v7.1 non dichiara legittima nessuna delle 59 email malevole,
  contro 3 della v6, e porta i falsi allarmi ad alto rischio da 11 a 1 su 41
  email legittime. In cambio alcuni casi malevoli passano da alto rischio a
  "da verificare". È anche più rapida: il tempo mediano scende da 34,6 a
  24,6 secondi sulle 68 email. Vedere `model-card-lite-v7.1.md`.
- La lista dei suffissi pubblici è aggiornata: i clienti di hosting condivisi
  come pages.dev, vercel.app o r2.dev sono domini distinti e non vengono più
  ricondotti alla piattaforma.
- I domini simili a un marchio sono valutati in proporzione alla lunghezza del
  nome, quindi domini comuni come like.com o email.com non generano più allarmi
  ad alto rischio. Vengono riconosciuti il combosquatting e il dominio ufficiale
  usato come sottodominio; i controlli valgono anche per From, Reply-To e
  Return-Path, e per il dominio dell'organizzazione del destinatario.
- I link mascherati, in cui il testo mostra un dominio e la destinazione è un
  altro, vengono segnalati, come i target `javascript:`, `data:` e `file:`.
  Vengono estratte anche le destinazioni da area, meta refresh e onclick.
- Gli allegati SVG sono analizzati come HTML: redirect via script, offuscamento,
  HTML smuggling ed esfiltrazione sono classificati. Aggiunti OneNote, CHM e
  XLL fra i formati a rischio.
- Le coordinate di pagamento sono controllate: IBAN validati con mod-97 nel
  testo nuovo, nel thread citato e negli allegati, annunci di variazione,
  discordanze e conti esteri. Gli IBAN sono mascherati nei report.
- Gli inviti del calendario vengono interpretati: le parti text/calendar e gli
  allegati .ics entrano nell'analisi dei link, con controllo fra organizzatore
  e mittente.
- Le finte risposte vengono riconosciute: un oggetto con prefisso di risposta
  senza riferimenti al thread viene segnalato, e una cronologia citata
  attribuita al destinatario senza threading è ad alto rischio.
- Motore e interfaccia usano ora una sola tabella di severità. I report portano
  i segnali del verdetto e le segnalazioni SIEM hanno identificativi stabili.
  Un test di contratto verifica che motore e interfaccia arrivino allo stesso
  verdetto.
- L'età dei domini dei link viene verificata con interrogazioni RDAP limitate e
  memorizzate, fino a cinque domini per email. Non avviene in modalità
  Solo locale.
- La pipeline AI non si chiama più Phi-4: la chiave dei report diventa
  `ai_analysis` e la cronologia salvata viene migrata al caricamento. Il codice
  BERT non utilizzato è stato rimosso.
- Su Windows con GPU NVIDIA, il runtime di accelerazione viene scaricato dalla
  stessa release dell'app e verificato con un'impronta inclusa nell'app, non
  più con quella pubblicata accanto al file. Un'app installata non scarica più
  il runtime di una release diversa.
- Corretto il ripiego DNS su HTTPS, che dopo il passaggio alla nuova lista dei
  suffissi pubblici restava disattivato in un'installazione pulita.

La pubblicazione degli installer richiede che FAST Lite v7.1 sia disponibile su
Hugging Face e superi `scripts/verify_fast_release_model.mjs`. Dataset, email,
adapter, pesi e report di valutazione locali non fanno parte dei sorgenti
dell'app.
