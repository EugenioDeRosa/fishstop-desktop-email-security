# Brand intelligence e verifica dell'identità

FishStop distingue tre evidenze: autenticazione del dominio del messaggio,
associazione fra azienda e dominio, autorizzazione della destinazione richiesta.
Un dominio autenticato può appartenere a un aggressore o a un account compromesso.
Nessuno di questi controlli garantisce da solo che un messaggio sia sicuro.

## Comportamento

- La firma DKIM viene verificata sui byte originali dell'EML usando la chiave DNS.
  Risultati di autenticazione dichiarati negli header non concedono fiducia.
  Firme parziali e messaggi incorporati privi di autenticazione originale restano
  non verificati. Chiavi DNS rimosse o rete assente possono impedire la verifica
  di messaggi vecchi senza costituire prova di phishing.
- Il registro locale e le directory firmate conservano fonte, data, scadenza,
  domini ufficiali, mittenti delegati e attività consentite.
- Il catalogo incluso contiene riferimenti circoscritti per Google, Microsoft,
  American Express, PayPal, Apple/iCloud, Netflix e Trust Wallet,
  con scadenza. Gmail e Outlook personali non identificano dipendenti del brand.
- Wikidata è un riferimento pubblico secondario: si confrontano fino a cinque
  candidati esatti, filtrando organizzazioni tramite tipo, sede e forma giuridica.
  Due aziende plausibili restano ambigue; un omonimo artistico non blocca più
  l'organizzazione corretta. Un elenco pubblico incompleto genera una richiesta di
  verifica, non una condanna automatica di impersonificazione.
- MX identifica il provider di ricezione. SPF/DMARC DNS, RDAP e presenza di BIMI
  sono informazioni di contesto; non provano l'identità aziendale. Certificati
  BIMI/VMC non vengono attualmente validati.
- Redirect, certificati CT e link trovati su siti ufficiali non autorizzano nuovi
  mittenti o servizi. Le deleghe richiedono host esatti; servizi per azioni
  richiedono anche un percorso specifico e uno scopo autorizzato.
- Per partner confermati e mittenti autenticati si conservano osservazioni di
  provider, Reply-To e destinazioni per segnalare cambiamenti in richieste
  sensibili. Queste osservazioni non aggiungono autorizzazioni al registro.

## Motore automatico di impersonificazione

Una passata AI dedicata estrae `claimed_brand` e `claimed_role` (rappresentante,
menzione, terza parte oppure incerto) dal nome visibile del mittente, dall'oggetto
e dal testo selezionato della mail e degli allegati PDF pertinenti, senza
consultare il catalogo dei marchi. Il testo dei PDF viene estratto durante la
scansione statica, con un massimo di tre pagine e un estratto limitato; PDF
senza testo o non leggibili non producono identità inventate. Il testo estratto
è trattato come dato non attendibile e la fonte rimane `attachment`.
Su Ollama l'estrazione usa il modello generale
`qwen3:4b-instruct-2507-q4_K_M`, separatamente dal modello addestrato per il rischio,
che tende a omettere i campi d'identità. Il modello di estrazione deve essere
installato nello stesso runtime; `FISHSTOP_IDENTITY_MODEL` permette di sostituirlo.
Un modello assente produce estrazione indisponibile, senza bloccare l'analisi del
contenuto. Il backend sperimentale MLX conserva il modello configurato per quel
backend; non è stato validato in questa prova Windows. Nome del modello e durata
si trovano nella telemetria e nel risultato dell'estrazione.
Richiede una citazione esatta e la relativa fonte; il motore rifiuta nomi e
citazioni non presenti nei campi visibili. Sono ammesse soltanto differenze negli
spazi e negli a capo; una fonte errata viene corretta solo quando la citazione
compare in un unico campo, conservando la citazione presente nell'input.
Se il nome proposto dall'AI coincide con l'intero nome visibile del mittente,
eventualmente seguito da ruoli generici, il campo del mittente può recuperare
una citazione omessa o parafrasata. Nomi di reparti espliciti e firme aziendali
con saluto possono recuperare un ruolo erroneamente classificato come menzione;
un ruolo `third_party` non viene promosso a rappresentanza. Nessuno di questi
controlli usa un elenco di marchi per estrarre un nome.
Il contenuto della mail è trattato come
dato non attendibile, mai come istruzione. Questo identifica una dichiarazione,
senza autenticare il mittente o decidere l'appartenenza aziendale.
Se la passata fallisce o restituisce prove non valide, si conserva soltanto
l'eventuale nome già estratto e fondato nel testo dall'analisi principale,
senza recupero basato sui nomi del catalogo. Lo stato della passata e il suo tempo
sono disponibili in `identity_analysis.extraction`; il tempo è registrato anche
in `performance.identity_extraction_seconds` e la chiamata nella telemetria
con stage `identity`. L'app raccoglie le prove prima della policy finale.
Le destinazioni sensibili vengono controllate anche
se manca il campo From. `impersonation.py` è puro e non effettua richieste di rete.

Il risultato è in `identity_analysis.impersonation`: segnali con fonte, peso,
polarità e famiglia, indice di sospetto 0–100, confidenza delle evidenze,
confidenza dell'associazione azienda-dominio, copertura, stato, decisione,
verifiche mancanti e versione delle regole. L'indice non è una probabilità.
I segnali correlati contribuiscono una volta per famiglia. Un supporto sul
mittente non cancella una contraddizione sulla destinazione dell'azione.

Domini imitativi del brand risolto vengono controllati dinamicamente, oltre
alla lista statica. Un'azione sensibile su un dominio imitativo è una prova
concreta; un mittente esterno, una casella personale, un Reply-To diverso o
un dominio recente, da soli, richiedono al massimo revisione. Le destinazioni
sensibili sono selezionate da CTA/ruolo `body_action`, non da tutti i link di
una newsletter. Età e DMARC `p=none` sono contesto debole. Dati mancanti restano
neutrali. Un dominio vecchio, un redirect o un provider condiviso non concedono fiducia.

Una contraddizione del mittente rispetto a un riferimento pubblico risolto
produce possibile impersonificazione e revisione, senza richiedere che il
riferimento sia nel catalogo. L'autenticazione mancante resta distinta dalla
contraddizione e non la nasconde. Una richiesta di verifica, credenziali o
modifica dell'account verso una casella personale non documentata tramite
`mailto:` genera una contraddizione sulla destinazione; diventa una prova forte
quando il riferimento è un registro o catalogo indipendentemente mantenuto e
con scopi espliciti. Un elenco pubblico incompleto, da solo, richiede revisione
e non condanna automaticamente il messaggio. Per i riferimenti
del registro vengono rispettati gli scopi delle azioni anche sui domini ufficiali;
la corrispondenza della destinazione non autentica automaticamente il mittente.
I suffissi generici di reparto/account si normalizzano soltanto nella risoluzione
del riferimento, dopo aver cercato il nome esatto; nomi e citazioni originali
rimangono nel report. Una piattaforma software che invia notifiche di un sito
terzo non viene automaticamente interpretata come rappresentante del fornitore.

Lookup Wikidata, DNS e RDAP lavorano in parallelo con un budget complessivo di
attesa di sei secondi e cache persistente. Le richieste Wikidata sono limitate
in dimensione, non seguono redirect e non usano proxy o credenziali ambientali.
I worker in corso hanno propri timeout; raggiungere il budget non attende il
loro completamento. La cache Wikidata è versionata per non riutilizzare gli
esiti ambigui della vecchia risoluzione.

Le impostazioni non mostrano sezioni, moduli o configurazioni per la protezione dell’identità.
Nel risultato si mostrano solo identità verificata, possibile impersonificazione
o verifica indisponibile, con una spiegazione breve. I dettagli sono chiusi
per impostazione predefinita e contengono solo domini, autenticazione e anomalie.
Indice, confidenza e controlli mancanti restano nel report strutturato. I record
non risolti non mostrano una falsa data di verifica. Il registro amministrativo resta disponibile nel backend per integrazioni gestite;
non è esposto nell’interfaccia delle impostazioni.

### Copertura attuale e limiti

Il catalogo viene aggiornato con le versioni dell'app: non esiste ancora un feed
remoto centralizzato. Per aziende sconosciute il riferimento online è Wikidata;
non è implementata una ricerca web generale o un servizio centrale di verifica.
Se Wikidata non documenta un'azienda, l'app segnala informazioni insufficienti,
senza chiedere all'utente di compilare un partner e senza indovinare la proprietà
del dominio. CT, ASN e BIMI/VMC validato restano fuori dal punteggio iniziale.
Il catalogo non pretende di enumerare tutti i mittenti o domini regionali di un brand.

## Aziende piccole e partner (solo amministratori)

Tramite il registro amministrativo del backend, facoltativamente aggiungere azienda, dominio ufficiale, eventuali
alias e mittente delegato, poi indicare come l'identità è stata confermata tramite
un canale già noto e indipendente dalla mail analizzata. La conferma dura 90 giorni
ed è revocabile. Non usare il contatto o il link fornito dalla mail sospetta come
unica prova.

La sfida TXT facoltativa dimostra il controllo del dominio, separatamente
dall'identità dell'azienda: pubblicare il valore generato sotto
`_fishstop-verification.<dominio>` e verificare la pubblicazione. Non aggiunge
automaticamente un partner e non concede fiducia alle mail ricevute.

I dati sono in `identity.sqlite` nella cartella dati dell'app. L'engine usa
`FISHSTOP_IDENTITY_DATA_DIR`, impostata automaticamente dall'app desktop.
Cache e conferme scadute non concedono fiducia. La verifica dell'identità di
un'azienda sconosciuta resta esplicitamente non risolta.

## Directory aziendali firmate

L'importazione JSON in Settings richiede una chiave pubblica Ed25519 configurata
dall'amministratore separatamente dal file importato. Non è inclusa una directory
centrale né una chiave di un fornitore commerciale.

Prima di avviare l'app impostare `FISHSTOP_IDENTITY_TRUSTED_KEYS` al percorso di un
JSON amministrato con struttura `{"admin-1":"<chiave pubblica raw base64>"}`.
Proteggere questo file e la cartella dati con i permessi del sistema operativo.
La chiave privata resta presso chi produce la directory; non viene importata.

Il bundle ha struttura:

```json
{
  "payload": {
    "key_id": "admin-1",
    "sequence": 1,
    "issued_at": 1791331200,
    "expires_at": 1791417600,
    "records": [{
      "brand": "Example Supplies",
      "aliases": ["Example"],
      "reference": "Independently verified procurement contact",
      "relations": [
        {"domain": "example-supplies.com", "role": "official", "scopes": ["sender", "reply", "visit_link"]},
        {"domain": "tenant.service.com", "role": "delegate", "scopes": ["visit_link"], "path_prefix": "/example"}
      ]
    }]
  },
  "signature": "<firma Ed25519 base64>"
}
```

Le date dell'esempio vanno aggiornate. La firma copre il payload serializzato con
`json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False).encode("utf-8")`. Validità massima: 90 giorni; massimo 1000 aziende.
Ogni importazione sostituisce atomicamente lo snapshot di quella chiave. Una
sequenza deve aumentare anche dopo la scadenza; una lista vuota revoca tutti i
record dell'emittente. Rimuovere o ruotare la chiave pubblica invalida le sue
conferme già importate. La protezione dal rollback vale per il database locale
esistente; il ripristino di un vecchio backup richiede gestione amministrativa.

Scopi disponibili: `sender`, `reply`, `visit_link`, `open_attachment`,
`provide_credentials`, `provide_information`, `pay_or_transfer`, `verify_account`,
`change_account_settings`, `claim_reward`. Una delega solo `sender` non autorizza
pagamenti o credenziali. Autenticazione e autorizzazione non sopprimono le regole
per sottrazione di credenziali, variazione sospetta di coordinate bancarie o altre
richieste dannose.

## Riferimenti

I casi di regressione ricavati dalle email Microsoft, Leroy Merlin, Intesa Sanpaolo
e Spotify verificano anche il recupero del brand quando il modello omette il nome.
Il riconoscimento considera alias, ruoli nel nome visibile e una breve firma
immediatamente successiva al corpo selezionato; non aggiunge altre conversazioni
o l'intero disclaimer. Un singolo indirizzo esplicito in un header malformato può
essere recuperato per il confronto, mai per autenticare il messaggio.

Un mittente estraneo a un riferimento mantenuto viene mostrato come possibile
impersonificazione e richiede revisione; il solo mismatch non promuove il verdetto
a phishing. Un dominio documentato resta non confermato quando manca una firma
DKIM verificata indipendentemente. I sottodomini Spotify non sono domini esterni.

- [Leroy Merlin: domini delle comunicazioni e false promozioni](https://www.leroymerlin.it/truffe-e-phishing/)
- [Spotify for Artists](https://artists.spotify.com/en/get-started)
- [Intesa Sanpaolo: sito ufficiale e phishing](https://www.intesasanpaolo.com/it/persone-e-famiglie/bisogni/sicurezza-digitale/phishing-bancario.html)

- [Authentication-Results e confini di fiducia, RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html)
- [Allineamento DMARC, RFC 7489](https://www.rfc-editor.org/info/rfc7489/)
- [RDAP, ICANN](https://www.icann.org/rdap/)
# Correlated reward impersonation

A grounded instruction to claim a time-limited reward can produce a phishing
verdict when it also claims to represent a company whose domain reference is
high confidence, contradicts that reference in the sender domain, and uses an
external actionable destination with no documented authorisation for claiming
rewards. Header SPF PASS on an unrelated domain does not authenticate the company.

This combination is evaluated separately from the identity score: an unrelated
sender alone still requires review. Unknown references, incidental company
mentions, official reward destinations and explicitly authorised delegates do
not qualify. Layout line breaks are normalised for reward evidence; ordinary
promotions and isolated urgency words cannot satisfy the full combination.
The checks reuse existing evidence and require no extra model or network calls.
