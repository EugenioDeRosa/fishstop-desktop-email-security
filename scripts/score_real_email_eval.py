"""Score exported results without running models or revealing labels to them."""
from pathlib import Path
from collections import Counter
import argparse, hashlib, json, statistics, math

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_SET=Path(__file__).resolve().parent if (Path(__file__).resolve().parent/'manifest.json').exists() else ROOT/'evaluation/real-email-testset-v1'

def read(path): return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
def ratio(n,d): return n/d if d else None

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--predictions',type=Path,required=True)
    p.add_argument('--dataset',type=Path,default=DEFAULT_SET)
    p.add_argument('--scope',choices=['all','balanced','body'],default='all')
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    manifest=json.loads((args.dataset/'manifest.json').read_text(encoding='utf-8'))
    for name in ['inputs','labels']:
        actual=hashlib.sha256((args.dataset/f'{name}.jsonl').read_bytes()).hexdigest()
        if actual!=manifest[f'{name}_sha256']:raise ValueError(f'{name} changed after freezing')
    labels={r['id']:r for r in read(args.dataset/'labels.jsonl')}
    inputs={r['id']:r for r in read(args.dataset/'inputs.jsonl')}
    rows=read(args.predictions); models={}; keys=set()
    for row in rows:
        key=(row['model'],row['id'])
        if row['id'] not in labels or key in keys:raise ValueError(f'Unknown or duplicated row: {key}')
        if not isinstance(row['model'],str) or not row['model']:raise ValueError('Missing model name')
        if row.get('prediction') not in [None,'phishing','legitimate','review','error']:raise ValueError(f'Invalid prediction: {key}')
        if row.get('json_valid') is not None and type(row['json_valid']) is not bool:raise ValueError(f'Invalid JSON validity: {key}')
        if row.get('seconds') is not None and (type(row['seconds']) not in [float,int] or not math.isfinite(row['seconds']) or row['seconds']<0):raise ValueError(f'Invalid latency: {key}')
        if not isinstance(row.get('semantics',{}),dict):raise ValueError(f'Invalid semantics: {key}')
        keys.add(key); models.setdefault(row['model'],{})[row['id']]=row
    selected=[r for r in labels.values() if args.scope=='all' or
              (args.scope=='balanced' and r['in_balanced_eml_pilot']) or
              (args.scope=='body' and r['body_verdict_scorable'])]
    results={}
    for model, predictions in sorted(models.items()):
        matrix={label:Counter({pred:0 for pred in ['phishing','legitimate','review','error','missing']}) for label in ['phishing','legitimate']}
        semantic={}; quote_checks=quote_grounded=0; measured_json=[]; times=[]
        for label in selected:
            row=predictions.get(label['id'],{})
            pred=row.get('prediction') or 'missing'; matrix[label['label']][pred]+=1
            if row.get('json_valid') is not None:measured_json.append(row['json_valid'])
            if row.get('seconds') is not None:times.append(row['seconds'])
            sem=row.get('semantics',{})
            for field,expected in label['expected_semantics'].items():
                tally=semantic.setdefault(field,{'correct':0,'annotated':0})
                tally['annotated']+=1
                tally['correct']+=field in sem and type(sem[field]) is type(expected) and sem[field]==expected
            input=inputs[label['id']]; text='\n'.join([input['subject'],input['body'],input['html_body_text']])
            for field in ['evidence','risk_evidence','signal_evidence']:
                if sem.get(field):
                    quote_checks+=1
                    quote_grounded+=isinstance(sem[field],str) and sem[field] in text
        totals={label:sum(c.values()) for label,c in matrix.items()}
        tp=matrix['phishing']['phishing']; fp=matrix['legitimate']['phishing']
        recall=ratio(tp,totals['phishing']); specificity=ratio(matrix['legitimate']['legitimate'],totals['legitimate'])
        results[model]={'expected_cases':len(selected),'completed_predictions':sum(sum(c[k] for k in ['phishing','legitimate','review','error']) for c in matrix.values()),
            'confusion_matrix':matrix,'accuracy':ratio(tp+matrix['legitimate']['legitimate'],len(selected)),
            'balanced_accuracy':(recall+specificity)/2 if recall is not None and specificity is not None else None,
            'phishing_recall':recall,'phishing_precision':ratio(tp,tp+fp),'false_positive_rate':ratio(fp,totals['legitimate']),
            'phishing_called_legitimate':matrix['phishing']['legitimate'],'legitimate_called_phishing':fp,
            'json_valid_rate_reported':ratio(sum(measured_json),len(measured_json)),'json_validity_measured_cases':len(measured_json),
            'median_seconds_reported':statistics.median(times) if times else None,'latency_measured_cases':len(times),
            'semantic_fields':semantic,'exact_quote_checks':quote_checks,'exact_quotes_grounded':quote_grounded}
    report={'dataset':str(args.dataset.resolve()),'inputs_sha256':manifest['inputs_sha256'],'labels_sha256':manifest['labels_sha256'],
            'scope':args.scope,'counts':dict(Counter(r['label'] for r in selected)),'models':results,
            'notes':'Missing, review and error predictions remain in recall/accuracy denominators. No inference of unreported JSON validity or latency. Semantic annotations are partial.'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'scope':args.scope,'counts':report['counts'],'models':list(results)}))

if __name__=='__main__':main()
