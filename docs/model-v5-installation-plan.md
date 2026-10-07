# FishSTOP AI v5: distribuzione e installazione

Aggiornamento del 7 ottobre 2026. Il modello v5 è pubblicato nel repository
pubblico `fishstop/fishstop-AI` su Hugging Face. Il download restituisce HTTP 200
senza autenticazione. Dimensione e SHA-256 nei metadati LFS coincidono con
l'artefatto locale verificato. Il catalogo usa una revisione immutabile.

## Artefatto da pubblicare

- File: `fishstop-qwen3-v5-Q4_K_M.gguf`, modello completo base + LoRA uniti.
- Percorso locale: Downloads dell'utente.
- Dimensione verificata: 2.497.280.448 byte, circa 2,5 GB.
- SHA-256 verificato: `bbb685dd1c8694d865b831c6874e54ba6a7b0ed0652f13ed55432ea8253a059e`.
- Repository: https://huggingface.co/fishstop/fishstop-AI
- Link di download: https://huggingface.co/fishstop/fishstop-AI/resolve/b12b12895c0e812eeace23452195d2aacf13de80/fishstop-qwen3-v5-Q4_K_M.gguf

Il checksum incluso nell'app viene verificato dopo ogni download completo e
impedisce di installare pesi diversi. I pesi rimangono separati dagli installer
e dal Git del codice.

## Comportamento implementato

Settings mostra **FishSTOP AI v5** e **Install FishSTOP AI v5**. Il clic:

1. Avvia il runtime incluso nell'app e scarica il GGUF con avanzamento visibile.
2. Verifica dimensione e SHA-256 senza caricare tutto il file in memoria.
3. Importa il blob e registra il tag `fishstop-qwen3:4b-finetuned-v5-q4_K_M`
   con il template e i token stop dell'esportazione v5.
4. Verifica il caricamento e aggiorna lo stato dell'app.

Il v5 è il modello di riferimento. Non c'è più il toggle per disabilitare il
fine-tune e non c'è ripiego silenzioso su Qwen standard. Le vecchie preferenze
non lo disattivano. La presenza del solo Qwen standard non nasconde Install.
Dopo l'installazione il modello viene usato offline. Remove elimina il tag v5
selezionato, lasciando intatti gli altri modelli dell'utente.

Un download interrotto riparte da zero; un GGUF già verificato viene riutilizzato
se l'importazione fallisce. Errori HTTP, dimensione errata, checksum errato e
risposte di importazione incomplete non vengono trattati come successo.
L'installazione è protetta da un lock per impedire importazioni concorrenti.

## Piattaforme

Windows, macOS Intel e Apple Silicon usano lo stesso GGUF v5 tramite Ollama
incluso nell'installer. Il workflow ora prepara Ollama anche per Apple Silicon,
che usa Metal. MLX resta esplicitamente sperimentale: richiede un export
fine-tuned dedicato e non scarica più Qwen standard come alternativa.

## Configurazione e controlli

Il catalogo è `src-tauri/model-catalog.json`; il template è
`src-tauri/model-template.txt`. Le dimensioni e il checksum del GGUF locale
coincidono con il catalogo. La build frontend e i 20 test Rust passano.
Un tag temporaneo creato con il payload dell'installer è stato importato e
caricato correttamente nel runtime locale; il tag temporaneo è stato rimosso.
Il download pubblico è stato avviato con successo e ha trasferito oltre 58 MB;
la verifica remota del checksum si basa sui metadati LFS. Non è stato ripetuto
il download completo di 2,5 GB durante il collaudo.

Restano il collaudo completo su profilo pulito, il riavvio offline e il collaudo
degli installer macOS su quei sistemi.
La verifica di qualità dei verdetti resta distinta dalla riuscita dell'installazione:
le prove v5 precedenti registrano ancora falsi positivi su notifiche OTP lecite.

## Riferimenti

- [Repository del modello](https://huggingface.co/fishstop/fishstop-AI)
- [API Ollama per importazione e creazione](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Limiti degli asset GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases): 2 GiB per file, meno del GGUF v5.
