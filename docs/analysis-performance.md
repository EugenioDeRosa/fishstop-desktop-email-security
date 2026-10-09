# Analisi delle attese evitabili — 7 ottobre 2026

La revisione esclude la brand intelligence. Il confronto del commit `ce48f99`
con il precedente mostra modifiche alla presentazione del progresso, senza nuove
chiamate AI, modifiche al prompt o variazioni dei budget di inferenza.

## Costi individuati e corretti

- La conclusione della splash attendeva una coda di animazioni, una transizione
  finale e il salvataggio della cronologia. Ora il report appare appena disponibile.
- Il frontend interrogava nuovamente lo stato del runtime prima di invocare
  l'analisi, che prepara già il modello nel backend. Ora usa i metadati già disponibili.
- Il backend scarica il modello dalla memoria al termine di ogni analisi,
  anche in caso di errore o annullamento, come richiesto dall'utente.
  Il periodo di mantenimento di 2 minuti serve solo a riutilizzare il modello
  tra le passate della stessa analisi; alla conclusione viene esplicitamente
  azzerato. L'analisi successiva ricarica il modello quando necessario.
- Il preriscaldamento Windows usava 3072 token, mentre l'analisi su GPU usava
  4096. Anche il numero di thread poteva differire. Ora entrambi usano una
  configurazione condivisa: 3072 per CPU e 4096 per GPU rilevata/macOS.

## Misura locale

Prova con il modello v5, runtime inizialmente vuoto e prompt vuoto, senza mail:

| Operazione | Tempo osservato |
| --- | ---: |
| Primo caricamento, contesto 3072 | 6,161 s |
| Riutilizzo con contesto 3072 | 0,007 s |
| Cambio del contesto a 4096 | 6,128 s |
| Riutilizzo con contesto 4096 | 0,006 s |

Questi sono tempi di preparazione del runtime; non sono un benchmark completo
dell'analisi e non dimostrano l'origine di un minuto aggiuntivo per ogni EML.

## Costi mantenuti

La modalità balanced esegue una passata primaria e un audit aggiuntivo solo
quando i segnali lo richiedono. Gli audit correlati sono raggruppati in una sola
chiamata. Il retry del JSON avviene solo quando l'output non è valido. I messaggi
lunghi possono richiedere più sezioni; i controlli di allegati si attivano solo
su formati pertinenti. Questi controlli non sono stati disabilitati.

La telemetria distingue tempo tecnico, pipeline AI e tempo delle chiamate al
modello. Il backend aggiunge `runtime_prepare_ms` ed `engine_process_ms` al campo
`performance`, per rendere distinguibile il caricamento dalla generazione.
Le correzioni native richiedono una nuova build e un riavvio dell'app.

## Integrated Radeon acceleration — 9 October 2026

On Windows AMD/Radeon machines the managed Vulkan runtime now defaults
`OLLAMA_IGPU_ENABLE` to `1`, allowing Ollama to consider integrated GPUs and
select GPU or CPU according to its runtime support and memory scheduling.
An explicit environment override is preserved, including `0` to disable it.
This applies to a newly started managed runtime; an already running external
Ollama server keeps its own configuration. NVIDIA CUDA selection is unchanged.

An isolated test with the installed Ollama v0.32.15 and the FishSTOP 4B Q4_K_M
model on Ryzen 7 PRO 7730U / integrated Radeon loaded 37/37 layers on Vulkan.
The runtime reported approximately 2.9 GB allocated on the GPU. For a 1445-token
prompt and 64 generated tokens, the cold request took 48.3 s versus 56.5 s on
CPU; a repeated cached-prefix request took 11.7 s versus 13.5 s. These short
measurements support enabling the GPU candidate on this machine, but do not
establish performance or long-term stability on every AMD/Intel system.
The existing Intel adapter filter is unchanged because no Intel device was
available for validation. Full-email correctness was not retested in this
microbenchmark. Logs and measurements remain local in
`output/gpu-check-2026-10-09`.
