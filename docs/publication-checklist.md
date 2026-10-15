# Verifica prima della pubblicazione

Verifica del 15 ottobre 2026 sul branch `dev`. Questa è una verifica tecnica
preliminare, non una certificazione di sicurezza o conformità legale.

## Esito

Il codice supera i controlli automatici eseguiti. Prima di promuovere il download
su LinkedIn occorre completare la distribuzione e provare gli installer reali.
Non è stata pubblicata una release né modificato `main` durante questa verifica.

## Controlli completati

- Build frontend riuscita.
- 28 test frontend superati. Corretto il test di accesso ospite, che non includeva
  il nuovo caricamento del nome locale: verificata anche la persistenza del nome
  e dello stesso spazio ospite dopo il sign out. Il test precedente bloccava CI.
- 36 test Rust superati.
- Motore Python: 335 test eseguiti, uno saltato, nessun fallimento.
- Landing page: 22 test superati; `main` e `dev` risultano allineati.
- `npm audit`: zero vulnerabilità note segnalate. `pip check`: nessun requisito
  installato incompatibile. Non equivalgono a un audit delle vulnerabilità di
  tutte le dipendenze Python/Rust o degli installer distribuiti.
- Nessuna corrispondenza nei pattern cercati per segreti nei file tracciati e
  nei blob di testo fino a 2 MB raggiungibili dai riferimenti pubblicati
  `origin/main`/`origin/dev`: 374 blob desktop e 30 landing. Non copre ogni formato
  di credenziale, oggetti non raggiungibili o copie esterne. La fixture EML
  tracciata è dichiarata sintetica e usa domini `.invalid`.
- I due repository GitHub risultano pubblici. Il sito pubblico si apre nel
  browser e comunica che la prima release è in arrivo.
- Download modello Fast Lite v2 e Pro v5 raggiungibili: HEAD HTTP 200 e dimensioni
  coerenti con i cataloghi, rispettivamente 1.107.409.408 e 2.497.280.448 byte.
  Non sono stati riscaricati e ricalcolati integralmente i checksum dei pesi.

## Da chiudere prima dell'annuncio

1. **Preparare la release effettiva.** Alla verifica, `origin/main` desktop è
   ancora `ff711b5`, 46 commit dietro il `dev` precedente a questa correzione.
   GitHub `/releases/latest` e il manifest `latest.json` restituiscono 404:
   mancano installer e canale pubblico di aggiornamento. Il trasferimento a
   `main` avvia la pipeline di produzione e richiede autorizzazione separata.
   Usare una versione superiore all'eventuale release già esistente al momento
   della pubblicazione e conservare la chiave di firma del canale ufficiale.

2. **Provare gli installer su macchine pulite.** Windows x64, Mac Intel e Apple
   Silicon: ingresso ospite e nome, primo download e annullamento, sign out
   durante il download, riapertura senza riscaricare modelli installati,
   rimozione Pro con ritorno a Fast, analisi EML, cronologia e modalità Solo
   locale. Provare un aggiornamento fra due versioni realmente installate,
   compresi rinvio, riavvio e conservazione di modelli/storico/preferenze.
   Vedere `desktop-updates.md`. Se una piattaforma non è provata, limitarne
   esplicitamente la disponibilità invece di dichiararla supportata.

3. **Chiudere il pacchetto dei sorgenti delle dipendenze.** Lo script
   `prepare_release_legal.py` raccoglie inventari e avvisi e archivia i sorgenti
   tracciati dell'app; non raccoglie automaticamente i sorgenti esatti di tutte
   le dipendenze. È ancora aperta la verifica richiesta in
   `distribution-licensing.md` per componenti GPL/MPL, runtime e componenti GPU.
   Conservare e distribuire quanto richiesto per le esatte versioni incluse.

4. **Chiudere la provenienza dei dati del modello.** Le model card e
   `training-data-rights.md` documentano i limiti della verifica. Restano da
   conservare date e prompt di generazione, termini applicabili, e chiarire
   l'uso degli output ChatGPT per il fine tuning. Per Lite v2 manca la prova
   completa che leghi dataset, run di training e artefatto distribuito. Non
   dedurre dai test o dalla natura sintetica una clearance completa dei diritti.

5. **Rotazione delle vecchie chiavi confermata dal proprietario il 15 ottobre 2026.**
   Le credenziali non sono state usate durante la verifica.

6. **Verificare firme e frizione di installazione.** La pipeline configura la
   firma Tauri degli aggiornamenti, ma non configura esplicitamente firma e
   notarizzazione Apple o Authenticode Windows. La firma updater non sostituisce
   quelle del sistema operativo. Decidere e verificare l'esperienza pubblica
   prima di indirizzare utenti non tecnici agli installer.

## Coerenza di documentazione e annuncio

- Aggiornare privacy e termini alla release realmente distribuita: nome ospite
  salvato localmente, toggle dei controlli aggiornamenti e stato corrente delle
  funzioni casella/OAuth. Alcune parti del sito descrivono ancora le «prossime
  build guest-only» e le release OAuth precedenti.
- Esplicitare prima del download dimensioni Fast/Pro, spazio disco richiesto,
  requisiti e connessione necessaria al primo avvio. Il README dice «solo su
  richiesta», mentre la preparazione iniziale può avviare automaticamente il
  download: rendere la spiegazione coerente con il flusso effettivo.
- Descrivere l'app come supporto al triage di email EML, con AI locale e controlli
  tecnici. I servizi esterni facoltativi possono ricevere URL, domini, IP e hash;
  evitare promesse assolute di funzionamento offline o assenza di comunicazioni.
- Non presentare Google/Microsoft o analisi dalla casella come già disponibili.
- Non dichiarare percentuali di accuratezza senza una valutazione indipendente,
  riproducibile e rappresentativa; falsi positivi e falsi negativi restano possibili.
- Per il primo annuncio è appropriato dichiarare lo stato beta/sperimentale e
  raccogliere feedback senza richiedere l'invio di email sensibili.
