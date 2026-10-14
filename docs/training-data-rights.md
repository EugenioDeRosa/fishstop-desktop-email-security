# Provenienza e diritti dei dati di training

Revisione: 14 ottobre 2026. Dati e report completi restano locali e ignorati dal Git.

## Evidenze disponibili

Il proprietario dichiara che gli scenari sintetici sono stati generati con ChatGPT Plus personale chiedendo solo esempi inventati di email malevole, senza incollare email reali o testi copiati. La dichiarazione è stata raccolta il 14 ottobre 2026; i prompt originali non sono stati ispezionati.
I builder locali v1-v5 leggono scenari e prompt locali; non risulta una importazione
di un corpus di email reali nella ricetta v5. Il dataset v5 ha 1.574 record tutti
marcati synthetic, con split e checksum coerenti con i manifest. Lo ZIP locale
coincide con la provenienza registrata nell'export; il checksum GGUF dell'export
coincide con il catalogo distribuito. Lite v1 ha 6.960 record, tutti marcati
synthetic (2.400/2.280/2.280); Lite v2 ne ha 7.152, tutti marcati synthetic
(2.528/2.312/2.312); non viene qui estesa a Lite la prova export della v5.

La scansione v5 non ha trovato candidati email su domini non riservati, numeri
telefonici nel formato cercato o i pattern di segreti cercati. Le 36 occorrenze
IBAN-shaped corrispondono a tre stringhe con checksum non valido. Lite v1 e v2 non
hanno corrispondenze per questi pattern. Non sono verifiche esaustive di nomi,
indirizzi fisici, attribuzione di testi o dati memorizzati nei pesi.

## Diritti: cosa è verificato e cosa manca

- Qwen3-4B-Instruct-2507 dichiara Apache-2.0; il modello FishStop v5 dichiara la
  stessa licenza. Conservare licenza upstream, attribuzione e modifiche.
- GPL dell'app, licenza dei pesi e diritti sui dati sono livelli distinti.
- I termini OpenAI attribuiscono all'utente i diritti sull'output nei limiti di
  legge, ma non garantiscono originalità o assenza di diritti di terzi e prevedono
  condizioni sull'uso dell'output per sviluppare modelli concorrenti.
- Generazione con ChatGPT non equivale automaticamente a clearance completa.
  La modalità Plus personale è confermata; restano da conservare date di generazione e termini allora applicabili; l'applicabilità
  della clausola al modello specializzato non è stata determinata, e non viene
  dichiarata una violazione accertata.
- La dichiarazione di non aver inserito email personali o testi copiati è stata raccolta; conservarne evidenza e rivedere i prompt originali se disponibili.
- Per i dataset reali usati solo in valutazione, acquisire separatamente fonte,
  autorizzazione/licenza e base per il trattamento; non trasferire automaticamente
  questi diritti ai dataset sintetici o alla pubblicazione dei pesi.
- Nessuna prova di assenza di memorizzazione nei pesi: prima di dichiararla servono
  test dedicati con canary controllati e tentativi di estrazione su dati autorizzati.

Il corpus non viene pubblicato con questa modifica. Non è stata attribuita una
nuova licenza al dataset né certificato un nulla osta legale completo.

## Controlli ripetibili

`python scripts/audit_training_privacy.py training/fishstop-v5 --output output/privacy-audit/v5.json`

Il report contiene conteggi e hash, non il testo delle email o i valori sospetti.
La scansione è euristica e solo in lettura. I report generati devono rimanere
fuori dal Git. Rivedere ogni corpus nuovo prima di sostituire il catalogo modello;
le conclusioni e la prova export v5 non si applicano automaticamente a v6/v7 o ai modelli Lite: per questi ultimi è stata eseguita una scansione separata.

Fonti ufficiali: https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507 e
https://openai.com/policies/eu-terms-of-use/ (consultate il 14 ottobre 2026).
