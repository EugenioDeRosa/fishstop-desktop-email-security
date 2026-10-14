# Privacy e collegamenti esterni

Revisione: 14 ottobre 2026. Ambito: branch dev guest-only; le precedenti release
con OAuth possono avere funzioni diverse. Questa mappa è ricavata dai chiamanti
attivi, non dalla sola presenza di una URL nel codice.

## Dati locali e modalità ospite

Le email EML, corpo, HTML, allegati e prompt AI sono elaborati sul dispositivo.
L'app non invia questi contenuti a un servizio AI remoto e non raccoglie le
email degli utenti per il training. L'ospite è uno spazio locale persistente,
non un account anonimo su un server. Cronologia e preferenze restano sul
computer; la cronologia è cifrata e le chiavi sono nel portachiavi del sistema.
Chi accede alla stessa sessione OS può riaprire lo spazio ospite.

La cronologia può contenere dati personali del messaggio. Clear history cancella
la cronologia dell'ospite, non gli EML originali, i report esportati, i backup o
ogni cache separata. Sign out non elimina la cronologia. La disinstallazione non
è una promessa di cancellazione di tutti i dati nelle cartelle utente.

## Mappa delle comunicazioni

| Destinatario | Quando | Dati trasmessi | Local only |
|---|---|---|---|
| VirusTotal / www.virustotal.com | Analisi, servizio abilitato e chiave presente; cache/quote permettendo | URL completi HTTP(S), domini mittente/Reply-To/Return-Path, hash SHA-256 allegati; chiave nell'header | Bloccato |
| AbuseIPDB / api.abuseipdb.com | Analisi, servizio abilitato e chiave presente | IP pubblici ricavati dal percorso SMTP; chiave nell'header | Bloccato |
| AlienVault OTX / otx.alienvault.com | Analisi, servizio abilitato e chiave presente | Indicatori esatti selezionati: URL, domini del mittente e hash; chiave nell'header | Bloccato |
| Spamhaus ZEN / zen.spamhaus.org e resolver DNS | Solo dopo attivazione esplicita, durante analisi; indipendente da AbuseIPDB | IP invertito nella query DNSBL; il resolver vede la query | Bloccato |
| ipwho.is | Solo dopo attivazione esplicita della geolocalizzazione | IP pubblici della catena di recapito | Bloccato |
| Resolver DNS configurato dal sistema | Verifica DKIM indipendente e osservazioni DNS | Nomi DNS, inclusi selettore DKIM e dominio; TXT/MX/NS e altri record previsti dal controllo | Bloccato |
| rdap.org e server RDAP dei registri | Analisi reputazione domini; verifiche identità | Dominio interrogato; rdap.org può redirigere al registro competente | Bloccato |
| data.iana.org | Caricamento/aggiornamento della tabella bootstrap RDAP | Richiesta della tabella dns.json, senza corpo email | Bloccato |
| Wikidata / www.wikidata.org | Analisi semantica con entità e verifica online del marchio, salvo cache | Nome del marchio/organizzazione estratto, ID di entità, richieste di proprietà | Bloccato |
| crt.sh | Helper legacy presente, senza chiamanti nel percorso attivo verificato | Se riattivato: ricerca di etichetta marchio in Certificate Transparency | Non usato; guard blocca richieste esterne |
| Siti HTTPS di organizzazioni e relativi redirect | Helper legacy presenti, senza chiamanti nel percorso attivo verificato | Se riattivati: GET della homepage/domino candidato per link e redirect; nessun corpo email o credenziale | Non usati; guard blocca richieste esterne |
| Hugging Face / huggingface.co e CDN/storage di download | Installazione modello scelta dall'utente, anche nella preparazione iniziale; richiesta versione/checksum | Percorso/revisione/file modello, range HTTP; nessuna email | Azione separata, consentita |
| GitHub / github.com e infrastruttura release/CDN | Controllo automatico aggiornamenti, download autorizzato e pacchetto GPU NVIDIA su richiesta dell'app | URL release/manifest/artefatto e range di download; nessuna email | Azione separata, consentita |
| Ollama/MLX su loopback | Inferenza locale e gestione runtime/modello | Prompt con testo e osservazioni selezionate; resta su localhost | Consentito |
| Browser esterno | L'utente apre privacy, termini, sorgenti o link del report | URL scelto, dati browser e connessione secondo il sito visitato | Azione separata |
| Google/Microsoft | Disabilitati nelle build standard; Coming soon | Nessuna chiamata di login/inbox della build standard | Non disponibili |

La URL VirusTotal può essere codificata base64 nell'endpoint: non è anonimizzazione.
URL e domini possono rivelare token, identificativi, intranet o relazioni aziendali;
anche un hash può consentire di riconoscere un allegato. Non inviare indicatori
riservati senza un'autorizzazione adeguata. Tutti i destinatari online e i CDN
possono osservare metadati di connessione, fra cui IP pubblico, orario e header
HTTP applicabili. La cifratura TLS non nasconde questi dati al destinatario.

Local only blocca durante l'analisi le connessioni esterne TCP/UDP e le risoluzioni
DNS nel motore, preservando il loopback per l'AI locale. Non è un firewall per
l'intera app: installazione modello, aggiornamenti e link aperti volontariamente
restano operazioni separate. I controlli disabilitati non sono esiti puliti.

## Cache e conservazione

VirusTotal: ~/.fishstop/vt-cache.sqlite3, condiviso tra processi sul medesimo
profilo OS, separato per impronta della chiave. Chiavi e URL di richiesta non sono
scritti in chiaro; le risposte possono contenere metadati degli indicatori.
Risultati riutilizzabili per un'ora, contatori per 24 ore; righe scadute rimosse
al successivo uso. Per cancellare la cache eliminare quel file con l'app chiusa.
Le altre cache di identità/reputazione possono conservare indicatori ed evidenze
con scadenze proprie: la scadenza logica non promette cancellazione immediata dei
byte da disco. I report esportati diventano file gestiti dall'utente e non sono
cancellati da Clear history. I file temporanei dell'analisi vengono rimossi al
termine ordinario; crash e backup OS possono lasciare copie.

## Sito di download e vecchie release

Il sito Streamlit non carica né analizza EML: Streamlit riceve metadati di visita,
GitHub serve informazioni sulle release e gli installer. Le rispettive policy
si applicano. Le vecchie release OAuth usano Google/Microsoft per autenticazione,
profilo e, dopo consenso, accesso read-only alla casella. Non equipararle alla
build guest-only di dev finché quest'ultima non viene distribuita.

Riferimenti: reputation.py, otx_intelligence.py, domain_identity.py,
brand_intelligence.py, network_policy.py, main.py, app-updates.ts e runtime Rust.
Le condizioni delle API restano indipendenti dalla GPL del codice.
