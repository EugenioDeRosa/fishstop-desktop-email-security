# FishSTOP 1.2.5

Release di sicurezza: nessun cambiamento nell'analisi o nei modelli.

- Pillow passa alla 13, che corregge 39 vulnerabilità note nei decoder di
  immagini. La ricerca dei QR code apre gli allegati solo come PNG, JPEG, GIF,
  BMP o WEBP: TIFF, EPS, WMF e gli altri formati non raggiungono più i decoder
  e risultano "non analizzabili", mai puliti.
- Aggiornate le librerie TLS usate per scaricare modelli e runtime (rustls,
  rustls-webpki e certificati radice, che non accettano più le CA emSign
  revocate) e quinn-proto.
- Il plugin degli aggiornamenti passa alla 2.14.1, che porta `zip` alla 9 e
  chiude gli avvisi sull'estrazione degli archivi.
- La CSP dell'app installata non permette più connessioni al server di
  sviluppo locale; resta solo nella configurazione di sviluppo.
- La mappa dei flussi di dati dichiara il ricorso a dns.google quando il
  resolver DNS del sistema non risponde.
