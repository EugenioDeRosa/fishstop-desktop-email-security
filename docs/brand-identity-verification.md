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

L'AI estrae `claimed_brand` e `claimed_role` (rappresentante, menzione, terza parte
oppure incerto), con un nome presente nel testo visibile. Non decide l'appartenenza
aziendale. L'app normalizza l'azione e raccoglie le prove prima della policy finale,
senza una nuova passata AI. Se il modello omette azienda o ruolo, le intestazioni
esplicite dei marchi del catalogo (ad esempio "Microsoft account" seguita da
"We detected...") e i display name esatti vengono recuperati localmente.
Semplici menzioni, nomi più lunghi e descrizioni di clienti non diventano
rappresentanza aziendale. Questo recupero identifica la dichiarazione, senza
autenticare il mittente. Le destinazioni sensibili vengono controllate anche
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

Lookup Wikidata, DNS e RDAP lavorano in parallelo con un budget complessivo di
attesa di sei secondi e cache persistente. Le richieste Wikidata sono limitate
in dimensione, non seguono redirect e non usano proxy o credenziali ambientali.
I worker in corso hanno propri timeout; raggiungere il budget non attende il
loro completamento. La cache Wikidata è versionata per non riutilizzare gli
esiti ambigui della vecchia risoluzione.

Le impostazioni normali mostrano solo una descrizione della protezione automatica.
Nel risultato si mostrano solo identità verificata, possibile impersonificazione
o verifica indisponibile, con una spiegazione breve. I dettagli sono chiusi
per impostazione predefinita e contengono solo domini, autenticazione e anomalie.
Indice, confidenza e controlli mancanti restano nel report strutturato. I record
non risolti non mostrano una falsa data di verifica. Il registro amministrativo
rimane facoltativo sotto **Advanced administrator tools**.

### Copertura attuale e limiti

Il catalogo viene aggiornato con le versioni dell'app: non esiste ancora un feed
remoto centralizzato. Per aziende sconosciute il riferimento online è Wikidata;
non è implementata una ricerca web generale o un servizio centrale di verifica.
Se Wikidata non documenta un'azienda, l'app segnala informazioni insufficienti,
senza chiedere all'utente di compilare un partner e senza indovinare la proprietà
del dominio. CT, ASN e BIMI/VMC validato restano fuori dal punteggio iniziale.
Il catalogo non pretende di enumerare tutti i mittenti o domini regionali di un brand.

## Aziende piccole e partner (solo amministratori)

In Settings → Advanced administrator tools → Verified partners, facoltativamente aggiungere azienda, dominio ufficiale, eventuali
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

- [Authentication-Results e confini di fiducia, RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html)
- [Allineamento DMARC, RFC 7489](https://www.rfc-editor.org/info/rfc7489/)
- [RDAP, ICANN](https://www.icann.org/rdap/)
