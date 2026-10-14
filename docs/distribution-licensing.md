# Distribuzione GPL di FishStop

Il codice originale è GPL-3.0-or-later, copyright 2026 Eugenio De Rosa.
`LICENSE` contiene il testo integrale; `COPYRIGHT` dichiara versione e opzione
per le versioni successive. Le dipendenze conservano le proprie licenze.
`oletools` e `pcodedmp` restano inclusi: non riduciamo i controlli Office.

## Sorgenti e installer

Ogni nuova release deve offrire, accanto agli installer, `fishstop-source.zip`
del medesimo commit e gli inventari/avvisi per ciascuna piattaforma. Il workflow
archivia esclusivamente file tracciati: niente email private, chiavi, output o
pesi locali. Conservare le release precedenti e i relativi sorgenti.

Gli installer includono `resources/legal/`: licenza del progetto, copyright,
avvisi e inventari delle versioni Python, frontend e Rust risolte nella build. La scheda
Settings mostra licenza, assenza di garanzia e collegamento ai sorgenti.

Le istruzioni di compilazione sono nel README. Chi modifica l'app deve usare
le proprie registrazioni OAuth e, per il proprio canale di aggiornamento, una
propria coppia di chiavi Tauri e propri endpoint. Le chiavi dell'autore non sono
necessarie per compilare o eseguire una propria versione. Per le build locali
senza canale di aggiornamento disattivare `bundle.createUpdaterArtifacts`.
Google OAuth può essere configurato con `FISHSTOP_GOOGLE_CLIENT_SECRET`; non
inserire credenziali nel repository. Le build standard sono guest-only: il workflow non prepara credenziali Google
e le risorse distribuite le escludono. Il secret di firma Tauri rimane necessario
soltanto per il canale di aggiornamento ufficiale. OAuth resta codice futuro,
disabilitato dal flag frontend e dalla feature Rust `account-access` non attiva.

## Verifica obbligatoria prima di una release pubblica

L'archivio del progetto e le sole URL upstream non sostituiscono il sorgente
corrispondente completo dei componenti coperti dalla GPL/MPL. Prima di rendere
pubblici gli installer:

- Conservare e fornire il sorgente delle esatte versioni distribuite di
  `pcodedmp`, degli altri componenti necessari al lavoro GPL combinato e delle
  parti MPL, inclusi eventuali patch e script di build.
- Rivedere anche le dipendenze Rust/frontend, PDFium e i runtime Ollama/MLX,
  incluse licenze e condizioni dei componenti GPU. L'inventario Python da solo
  non dimostra la conformità dell'intero installer.
- Verificare che tutti gli avvisi richiesti siano inclusi e accessibili, e che
  l'archivio corrisponda effettivamente alla build pubblicata.
- Rendere disponibili i sorgenti senza autenticazione: un repository privato
  non soddisfa la distribuzione pubblica. Non cambiare la visibilità prima
  della bonifica e delle altre verifiche richieste.

Queste modifiche preparano il progetto GPL; non certificano retroattivamente
gli installer già pubblicati. Non rimuovere i loro sorgenti durante la pulizia.

## Servizi, modello e marchi

La GPL consente l'uso commerciale del software, ma non concede accesso alle
API: VirusTotal Public, OTX gratuito e Spamhaus pubblico hanno restrizioni
proprie. Gli utenti devono scegliere piani/autorizzazioni compatibili con il
loro uso. Le API e i loro dati non sono rilicenziati dalla GPL di FishStop.

I pesi scaricati separatamente mantengono la licenza dichiarata nel repository
del modello. Dati personali, chiavi e dati di training non diventano pubblici
per effetto della GPL. La licenza non concede diritti sui marchi o il permesso
di rappresentare un fork come versione ufficiale; restano leciti i riferimenti
veritieri all'origine del progetto.
