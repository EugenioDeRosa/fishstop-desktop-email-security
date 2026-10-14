"""
bert_calibration.py - Inferenza calibrata per il classificatore BERT phishing.

Perche' esiste: il softmax grezzo di un transformer fine-tuned tende ad
essere overconfident (Guo et al., 2017, "On Calibration of Modern Neural
Networks"), soprattutto nelle epoche finali dove la loss di training
continua a scendere mentre quella di validazione ristagna o risale (visto
empiricamente durante il training di questo modello). Questo modulo applica:

  1. Temperature scaling: divide i logit per una temperatura T stimata sul
     validation set PRIMA del softmax. T=1.0 e' un no-op (softmax grezzo),
     usato come fallback quando non e' ancora disponibile una calibrazione.
  2. Una soglia decisionale derivata da una curva ROC/PR sul validation set
     (invece del 50% implicito), con una banda di incertezza intorno ad
     essa, salvate insieme al modello in un file calibration.json.

Il file calibration.json viene prodotto da src/train.py e va pubblicato
insieme al modello (vedi src/views/backend.py::get_calibration).

Import identico sia lato training (Colab, per calcolare T e la soglia) sia
lato inferenza (app Streamlit), cosi' la logica di decisione non puo' piu'
divergere tra le due fasi come era successo in passato per il preprocessing
del testo (bert-base vs distilbert, normalizzazione diversa tra notebook e
app).
"""

import json
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

# Fallback usati SOLO se calibration.json non e' ancora stato pubblicato
# insieme al modello. Riproducono ESATTAMENTE il comportamento legacy:
# softmax grezzo, "phishing" sopra il 65%, "legitimate" sotto il 35%,
# "uncertain" nella banda 35-65 (soglia 0.50 +/- banda 0.15 per lato).
DEFAULT_TEMPERATURE = 1.0
DEFAULT_THRESHOLD = 0.50
DEFAULT_BAND = 0.30  # larghezza TOTALE della banda di incertezza attorno alla soglia
DEFAULT_POSITIVE_LABEL_ID = 1


def calibrated_probabilities(logits: torch.Tensor, temperature: float = DEFAULT_TEMPERATURE) -> torch.Tensor:
    """
    Applica temperature scaling + softmax. Con temperature=1.0 e' identico
    al softmax grezzo usato in precedenza (nessuna regressione se
    calibration.json non e' disponibile).
    """
    t = max(float(temperature), 1e-6)
    return torch.softmax(logits / t, dim=1)


def classify(prob_phishing: float, threshold: float = DEFAULT_THRESHOLD, band: float = DEFAULT_BAND) -> str:
    """
    Decide 'phishing' / 'legitimate' / 'uncertain' a partire dalla
    probabilita' di phishing calibrata (0-1, non percentuale).

    threshold: punto centrale di decisione stimato sul validation set
        (es. il punto che massimizza F1 sulla curva PR calcolata su
        probabilita' GIA' calibrate). Con i default legacy vale 0.50.
    band: larghezza totale della banda di incertezza centrata sulla
        soglia. Con i default legacy (threshold=0.50, band=0.30) si
        riproduce esattamente la banda 35%-65% usata in precedenza.
    """
    half = band / 2
    if prob_phishing >= threshold + half:
        return "phishing"
    if prob_phishing <= threshold - half:
        return "legitimate"
    return "uncertain"


def fit_temperature(logits: torch.Tensor, labels: torch.Tensor) -> float:
    """Stima una temperatura positiva minimizzando la cross-entropy di validation."""
    logits = torch.as_tensor(logits, dtype=torch.float32).detach().cpu()
    labels = torch.as_tensor(labels, dtype=torch.long).detach().cpu()
    if logits.ndim != 2 or logits.shape[1] != 2 or len(logits) != len(labels):
        raise ValueError("Expected binary logits shaped [n_samples, 2] and one label per sample")
    if len(labels) < 2 or len(torch.unique(labels)) < 2:
        raise ValueError("Temperature scaling requires both classes in validation")

    # Ottimizziamo log(T), cosi' la temperatura resta sempre strettamente positiva.
    log_temperature = torch.nn.Parameter(torch.zeros(1))
    optimizer = torch.optim.LBFGS([log_temperature], lr=0.1, max_iter=100, line_search_fn="strong_wolfe")

    def closure():
        optimizer.zero_grad()
        loss = F.cross_entropy(logits / log_temperature.exp(), labels)
        loss.backward()
        return loss

    optimizer.step(closure)
    return max(float(log_temperature.detach().exp().item()), 1e-6)


def optimal_f1_threshold(prob_phishing, labels) -> tuple[float, float]:
    """Restituisce soglia e F1 migliori sulla validation calibrata."""
    # Lazy import: scikit-learn serve al training, non al runtime Streamlit.
    from sklearn.metrics import precision_recall_curve

    probabilities = np.asarray(prob_phishing, dtype=float)
    labels = np.asarray(labels, dtype=int)
    precision, recall, thresholds = precision_recall_curve(labels, probabilities)
    if thresholds.size == 0:
        return DEFAULT_THRESHOLD, 0.0
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    best = int(np.nanargmax(f1))
    return float(thresholds[best]), float(f1[best])


def selective_uncertainty_band(
    prob_phishing,
    labels,
    threshold: float,
    target_accuracy: float = 0.95,
    minimum_coverage: float = 0.80,
) -> tuple[float, float, float]:
    """
    Trova la banda simmetrica piu' stretta che raggiunge la target accuracy
    sui campioni non astenuti, preservando almeno minimum_coverage.
    """
    probabilities = np.asarray(prob_phishing, dtype=float)
    labels = np.asarray(labels, dtype=int)
    distances = np.abs(probabilities - float(threshold))
    candidates = np.unique(np.concatenate(([0.0], distances)))
    fallback = (0.0, 0.0, 1.0)

    for half_width in candidates:
        decided = distances >= half_width
        coverage = float(decided.mean())
        if not decided.any() or coverage < minimum_coverage:
            continue
        predictions = (probabilities[decided] >= threshold).astype(int)
        accuracy = float((predictions == labels[decided]).mean())
        if accuracy > fallback[1]:
            fallback = (float(half_width * 2), accuracy, coverage)
        if accuracy >= target_accuracy:
            return float(half_width * 2), accuracy, coverage
    return fallback


def fit_calibration(
    logits: torch.Tensor,
    labels: torch.Tensor,
    positive_label_id: int = DEFAULT_POSITIVE_LABEL_ID,
    target_accuracy: float = 0.95,
    minimum_coverage: float = 0.80,
) -> dict:
    """Stima tutti i parametri da salvare in calibration.json."""
    temperature = fit_temperature(logits, labels)
    probabilities = calibrated_probabilities(logits, temperature)[:, positive_label_id].cpu().numpy()
    threshold, validation_f1 = optimal_f1_threshold(probabilities, labels)
    band, selective_accuracy, selective_coverage = selective_uncertainty_band(
        probabilities,
        labels,
        threshold,
        target_accuracy=target_accuracy,
        minimum_coverage=minimum_coverage,
    )
    return {
        "version": 1,
        "method": "temperature_scaling",
        "temperature": temperature,
        "threshold": threshold,
        "band": band,
        "positive_label_id": int(positive_label_id),
        "validation_f1_at_threshold": validation_f1,
        "selective_accuracy": selective_accuracy,
        "selective_coverage": selective_coverage,
        "target_selective_accuracy": float(target_accuracy),
        "minimum_selective_coverage": float(minimum_coverage),
    }


def save_calibration(calibration: dict, path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(calibration, indent=2), encoding="utf-8")
    return destination
