"""Freeze local real EML fixtures for the same 4B / 1.7B evaluation."""
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from html.parser import HTMLParser
from email.utils import parseaddr
import json, hashlib, re, random, zipfile
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/real-email-testset-v1'
RAW = Path(r'C:\Users\DEROSAEU\Desktop\raw')
POT = Path(r'C:\Users\DEROSAEU\Documents\Progetti\DATASET EMAIL\MALICIOUS\email_sample_phishingpot')
TEST = POT.parent / 'EML TEST'

class HtmlText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.links, self.skip = [], [], 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'head'): self.skip += 1
        if tag in ('p', 'br', 'div', 'tr', 'li'): self.parts.append('\n')
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if href: self.links.append(href)
    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'head') and self.skip: self.skip -= 1
    def handle_data(self, data):
        if not self.skip: self.parts.append(data)

def sha(data): return hashlib.sha256(data).hexdigest()
def norm(text): return re.sub(r'\s+', ' ', text).strip()
def jsonl(path, rows):
    path.write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in rows), encoding='utf-8')

def extract(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    plain, html, urls, attachments, defects = [], [], [], [], []
    for part in msg.walk():
        defects.extend(type(d).__name__ for d in part.defects)
        filename = part.get_filename()
        if filename or part.get_content_disposition() == 'attachment':
            data = part.get_payload(decode=True) or b''
            attachments.append({'name': filename, 'content_type': part.get_content_type(),
                                'size': len(data), 'sha256': sha(data),
                                'disposition': part.get_content_disposition()})
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'): continue
        data = part.get_payload(decode=True) or b''
        try: text = data.decode(part.get_content_charset() or 'utf-8')
        except (UnicodeError, LookupError): text = data.decode('utf-8', errors='replace')
        if part.get_content_type() == 'text/html':
            parser = HtmlText(); parser.feed(text)
            html.append(norm(' '.join(parser.parts))); urls.extend(parser.links)
        else: plain.append(text.strip())
        if part.get_content_type() == 'text/plain':
            urls.extend(re.findall(r'https?://[^\s<>"\']+', text))
    plain_text = '\n\n'.join(plain); html_text = '\n\n'.join(html)
    return {'subject': str(msg.get('Subject', '')), 'sender': str(msg.get('From', '')),
            'reply_to': str(msg.get('Reply-To', '')), 'body': plain_text,
            'html_body_text': html_text, 'urls': list(dict.fromkeys(urls)),
            'attachments': attachments, 'mime_defects': sorted(set(defects))}

# category, expected observable behavior, body verdict scorable, optional semantic fields
ANNOTATIONS = {
 'Cambio password RDAP.eml': ('password_reminder', 'Promemoria di cambio password, senza raccolta di password o OTP.', True, {}),
 'Creazione carta virtuale del 30_06_2026.eml': ('bank_notification', 'Notifica carta virtuale: telefonare se non riconosciuta; non è una ricevuta.', True, {'channel':'phone'}),
 'Express yourself_ tune your artist profile to perfection.eml': ('marketing', 'Newsletter Spotify: tracking e promozione non bastano a provare phishing.', True, {}),
 'Your music is live_ See how it\'s performing.eml': ('marketing_statistics', 'Notifica Spotify e statistiche musicali, senza raccolta di segreti.', True, {}),
 'Last day program.eml': ('university_schedule', 'Organizzazione esame e appuntamento online ordinario.', True, {}),
 'Re_ Aggiornamento tirocinio e informazioni per richiesta Relatore di tesi.eml': ('quoted_security_discussion', 'Discussione di tesi: la citazione del phishing non è un attacco.', True, {}),
 'test.eml': ('calendar_attachment', 'Calendario universitario allegato; il PDF non implica phishing.', True, {}),
 'test3.eml': ('vpn_workflow', 'Configurazione VPN e appuntamento; distinguere menzione di credenziali da furto.', True, {}),
 'test4.eml': ('authentication_test', 'Email di prova SPF/DKIM con firma aziendale.', True, {'action':'info','channel':'none'}),
 'test5.eml': ('internship_thread', 'Risposta operativa e scheda presenze; citazioni di sicurezza lecite.', True, {}),
 'test6.eml': ('training_certificates', 'Scambio aziendale di certificati formazione nel thread.', True, {}),
 'test7.eml': ('remote_support_policy', 'Indicazioni aziendali per Neurons/TeamViewer; non dedurre malware dai nomi.', True, {}),
 'test8.eml': ('token_activation', 'Attivazione Fortitoken tramite procedura allegata, senza inoltro di OTP.', True, {}),
 '(Nuova dichiarazione approvata - Da LS LexJus Sinacta).eml': ('office_document_lure', 'Documento dichiarato OneDrive con CTA Sway/Forms; non inventare password richieste nel corpo.', False, {'action':'visit_link','channel':'link'}),
 'recogida de pedido.eml': ('iban_diversion', 'Nuova destinazione bancaria in contesto di pagamento: rilevare conto aggiornato, senza inventare importi. La frode è confermata dalla raccolta, non dimostrabile dal solo estratto.', False, {'payment_destination_change':True}),
 'Violazione dei dati personali a causa di presunte attivita dannose..eml': ('sextortion', 'Ricatto e richiesta Bitcoin; non credere alla dichiarazione di compromissione.', True, {'action':'payment','payment_asset':'Bitcoin','coercion':True}),
 'sample-10.eml': ('microsoft_security_lure', 'Finto avviso Microsoft con Report The User su destinazione estranea; non inventare raccolta OTP.', True, {'action':'verify_account','channel':'link'}),
 'sample-1159.eml': ('password_expiry', 'Password in scadenza e mantenimento tramite link; verificare il canale.', True, {}),
 'sample-1250.eml': ('bank_html_attachment', 'Pagamento Capital One da verificare attraverso allegato HTML.', False, {'channel':'attachment'}),
 'sample-1257.eml': ('sharepoint_document_lure', 'Contratto SharePoint collegato a storage esterno.', True, {'action':'visit_link','channel':'link'}),
 'sample-1261.eml': ('purchase_order_html', 'Richiesta commerciale con falso foglio Xls.htm; la prova richiede allegato.', False, {}),
 'sample-1266.eml': ('wire_transfer_iso', 'Presunta ricevuta bancaria in quotation.iso; non chiamarla normale PDF.', True, {}),
 'sample-1340.eml': ('suspension_pdf', 'Sospensione account con PDF; corpo scarno, richiede allegato.', False, {}),
 'sample-3544.eml': ('fedex_obfuscation', 'Verifica consegna FedEx con contenuto offuscato.', True, {}),
 'sample-3641.eml': ('fine_encrypted_archive', 'Multa con ZIP protetto: 0808 è password archivio, non OTP richiesto.', False, {'action':'open_attachment','channel':'attachment'}),
 'sample-4376.eml': ('mortgage_noise', 'Offerta assicurativa e disturbo: sola provenienza non basta a provare il verdetto dal corpo.', False, {}),
 'sample-4749.eml': ('advance_fee', 'Eredità/fondi bancari abbandonati, riservatezza e contatto esterno.', True, {}),
 'sample-5092.eml': ('mailbox_full', 'Plain text minimale ma HTML con mailbox piena e pulsante Take action.', True, {}),
 'sample-5923.eml': ('prize_attachments_noise', 'Premio Albert Heijn, rumore e allegati: confrontare MIME completo.', False, {}),
 'sample-6229.eml': ('crypto_prize', 'Presunto premio Bitcoin con registrazione su IP; non attribuire invio password senza prova.', True, {}),
 'sample-6533.eml': ('data_deletion_attachments', 'Minaccia cancellazione dati con DOCX/PDF e corpo scarno.', False, {}),
 'sample-7262.eml': ('mobileconfig', 'Oggetto pagamento e corpo deliverability incoerenti; tre profili mobileconfig.', False, {}),
 'sample-803.eml': ('travel_cloudrun', 'Promozione 123milhas su tenant Cloud Run: distinguere link dichiarato e destinazione.', False, {}),
 'sample-8085.eml': ('bonus_noise', 'Bonus urgente e testo casuale; evitare inferenze basate solo sull’oggetto.', False, {}),
 'sample-8370.eml': ('dhl_customs', 'Pagamento dazi DHL entro 48 ore su dominio estraneo.', True, {'action':'payment','channel':'link'}),
 'sample-8532.eml': ('wallet_app_lure', 'Invito al download di wallet: natura del software non dimostrata dal solo testo.', False, {}),
 'sample-1.eml': ('bank_rewards', 'Premio Bradesco/Livelo in scadenza e CTA su dominio estraneo.', True, {'action':'claim_reward','channel':'link'}),
 'sample-5.eml': ('chase_reactivation', 'Blocco Chase e riattivazione urgente su link estraneo.', True, {'action':'verify_account','channel':'link'}),
 'sample-35.eml': ('paypal_phone_change', 'Finta notifica PayPal: No it wasn’t me apre mailto verso Gmail, mentre i link di contorno sono ufficiali.', True, {'action':'verify_account'}),
 'sample-77.eml': ('sextortion_obfuscated', 'Oggetto rapporto pagamento ma corpo con ricatto sessuale e Bitcoin, scritto a lettere separate.', True, {'action':'payment','coercion':True}),
 'sample-95.eml': ('wallet_suspension', 'Sospensione Trustwallet e Confirm my wallet tramite link.', True, {'action':'verify_account','channel':'link'}),
 'sample-112.eml': ('crypto_balance_lure', 'Promette 75 BTC e consegna login; non è una richiesta di divulgare credenziali.', True, {}),
 'sample-129.eml': ('device_scan_newsletter', 'Invito a scansione dispositivo innestato in newsletter universitaria.', False, {}),
 'sample-1000.eml': ('tax_refund_pdf', 'Presunto credito fiscale con PDF; valutazione completa richiede allegato.', False, {'action':'open_attachment','channel':'attachment'}),
}

def main():
    OUT.mkdir(parents=True, exist_ok=True); (OUT/'eml').mkdir(exist_ok=True)
    selected = [(p, 'legitimate', 'custom_legitimate') for p in sorted((RAW/'custom_legitimate').glob('*.eml'))]
    for filename in ['(Nuova dichiarazione approvata - Da LS LexJus Sinacta).eml', 'recogida de pedido.eml', 'sample-10.eml', 'Violazione dei dati personali a causa di presunte attivita dannose..eml']:
        selected.append((RAW/'custom_phishing'/filename, 'phishing', 'custom_phishing'))
    selected += [(p, 'phishing', 'EML TEST') for p in sorted(TEST.glob('*.eml'))]
    selected += [(POT/f'sample-{n}.eml', 'phishing', 'phishingpot') for n in [1,5,35,77,95,112,129,1000]]
    random.Random(20261012).shuffle(selected)
    labels, inputs, seen, seen_content, duplicates = [], [], {}, {}, []
    old_hashes = set()
    old = ROOT/'evaluation/qwen-light-testset-v1/labels.jsonl'
    if old.exists(): old_hashes = {json.loads(line)['sha256'] for line in old.read_text(encoding='utf-8').splitlines()}
    train_rows = []
    for path in (ROOT/'training').rglob('*.jsonl'):
        if path.name not in ('train.jsonl','train_sft.jsonl','validation.jsonl','val.jsonl'): continue
        for line in path.read_text(encoding='utf-8').splitlines():
            r=json.loads(line); email=r.get('email', {})
            if email: train_rows.append((str(path.relative_to(ROOT)), norm(str(email.get('body','')))))
    for path, label, source in selected:
        original = path.read_bytes(); raw = original; transform = None
        if path.name == 'recogida de pedido.eml':
            original_input = extract(original)
            body = original_input['body']
            start = body.index('*De:* Mamini, Micaela')
            end = body.index('Venerdì 8 maggio 2026')
            excerpt = body[start:end].strip().replace('\r\n','\n').replace('\r','\n')
            assert 'cuenta\r\nbancaria actualizada' in excerpt or 'cuenta\nbancaria actualizada' in excerpt
            msg=EmailMessage(); msg['From']= 'Mamini, Micaela <micaela.mamini.ext@cefla.it>'
            msg['To']='contabilidad@bucoclinics.com'; msg['Subject']='RE: recogida de pedido'
            msg['Date']='Tue, 12 May 2026 12:32:00 +0200'
            msg['Message-ID']='<fishstop-eval-iban-excerpt@example.invalid>'
            msg.set_content(excerpt); raw=msg.as_bytes(policy=policy.SMTP)
            transform={'type':'thread_excerpt','start_marker':'*De:* Mamini, Micaela',
                       'end_marker_exclusive':'Venerdì 8 maggio 2026',
                       'note':'Corpo estratto senza riscrittura: conto PT50, richiesta prova pagamento, risposta cliente e conto aggiornato. Header ricostruiti da quelli citati; nessuna autenticazione originale.'}
        row=extract(raw); digest=sha(raw)
        fingerprint=sha((row['subject']+'\n'+norm(row['body'])+'\n'+norm(row['html_body_text'])+'\n'+json.dumps(row['attachments'],sort_keys=True)).encode())
        prior = seen.get(digest) or seen_content.get(fingerprint)
        if prior:
            duplicates.append({'source_path':str(path),'duplicate_of':prior}); continue
        id=f'E{len(labels)+1:03d}'; file=f'eml/{id}.eml'
        seen[digest]=id; seen_content[fingerprint]=id; (OUT/file).write_bytes(raw)
        category, behavior, body_scorable, expected = ANNOTATIONS[path.name]
        # Exact body containment is a limited audit; no claim about absent external training data.
        texts=[norm(t) for t in [row['body'],row['html_body_text']] if len(norm(t))>=120]
        matches=sorted({p for p,b in train_rows if any(t in b for t in texts)})
        labels.append({'id':id,'file':file,'label':label,'category':category,'expected_behavior':behavior,
                       'expected_semantics':expected,'body_verdict_scorable':body_scorable,
                       'label_basis':'user_confirmed_collection' if label=='legitimate' or source!='phishingpot' else 'malicious_collection_and_static_content_review',
                       'annotation_status':'single_reviewer_static','source_collection':source,'source_path':str(path),
                       'source_sha256':sha(original),'sha256':digest,'content_fingerprint':fingerprint,
                       'transformation':transform,'previous_eval_exposure':sha(original) in old_hashes,
                       'local_training_exact_body_matches':matches,'training_exposure':'unknown_beyond_local_exact_audit',
                       'subject':row['subject'],'split':'test_only','live_destination_verified':False})
        inputs.append({'id':id,**row})
    assert Counter(r['label'] for r in labels)=={'phishing':31,'legitimate':13}
    # Balanced full-EML pilot: all legitimate fixtures and 13 diverse malicious fixtures.
    core_categories={'office_document_lure','iban_diversion','sextortion','microsoft_security_lure','password_expiry',
                     'bank_html_attachment','sharepoint_document_lure','wire_transfer_iso','fine_encrypted_archive',
                     'advance_fee','mailbox_full','dhl_customs','bank_rewards'}
    core=[r['id'] for r in labels if r['label']=='legitimate' or r['category'] in core_categories]
    assert len(core)==26
    for r in labels: r['in_balanced_eml_pilot']=r['id'] in core
    jsonl(OUT/'labels.jsonl',labels); jsonl(OUT/'inputs.jsonl',inputs)
    jsonl(OUT/'predictions-template.jsonl',[{'model':model,'id':r['id'],'prediction':None,'seconds':None,'json_valid':None,'semantics':{}} for model in ['4B','1.7B'] for r in labels])
    manifest={'version':1,'created':'2026-10-12','counts':dict(Counter(r['label'] for r in labels)),
              'balanced_eml_pilot_ids':core,'body_scorable_ids':[r['id'] for r in labels if r['body_verdict_scorable']],
              'duplicate_sources_skipped':duplicates,'inputs_sha256':sha((OUT/'inputs.jsonl').read_bytes()),
              'labels_sha256':sha((OUT/'labels.jsonl').read_bytes()),'items':labels}
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    catalog=['# Catalogo email reali — test 4B / 1.7B','','| ID | Etichetta | Sorgente | Oggetto | Caso | Verdetto dal corpo | Cosa verificare |','|---|---|---|---|---|---|---|']
    for r in labels:
        catalog.append('| '+' | '.join(str(x).replace('|','\\|').replace('\n',' ') for x in [r['id'],r['label'],r['source_collection'],r['subject'],r['category'],'sì' if r['body_verdict_scorable'] else 'solo valutazione completa',r['expected_behavior']])+' |')
    (OUT/'CATALOGO.md').write_text('\n'.join(catalog)+'\n',encoding='utf-8')
    jsonl(OUT/'training-exposure-audit.jsonl',[{k:r[k] for k in ['id','previous_eval_exposure','local_training_exact_body_matches','training_exposure']} for r in labels])
    (OUT/'score_results.py').write_bytes((ROOT/'scripts/score_real_email_eval.py').read_bytes())
    for r in labels:
        assert sha((OUT/r['file']).read_bytes())==r['sha256']
        if not r['transformation']: assert r['source_sha256']==r['sha256']
    (OUT/'SHA256SUMS.txt').write_text(''.join(f"{sha(p.read_bytes())}  {p.relative_to(OUT).as_posix()}\n" for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.txt'),encoding='utf-8')
    with zipfile.ZipFile(OUT.with_suffix('.zip'),'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUT.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(OUT))
    print(json.dumps({'counts':manifest['counts'],'balanced_pilot':len(core),'duplicates_skipped':len(duplicates),'previous_eval_exposure':sum(r['previous_eval_exposure'] for r in labels),'local_train_matches':sum(bool(r['local_training_exact_body_matches']) for r in labels)}))

if __name__=='__main__':main()
