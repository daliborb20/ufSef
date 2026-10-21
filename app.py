import os, re, sqlite3, json, csv, io, time, threading, uuid, ctypes
from ctypes import wintypes
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, flash, Response, jsonify, send_file
from dotenv import load_dotenv
import requests
import truststore

truststore.inject_into_ssl()
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'local')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, 'sef.sqlite3')
DPAPI_KEY_FILE = os.path.join(BASE_DIR, 'sef_api_key.dat')
PDF_DIR = os.path.join(BASE_DIR, 'documents')
_last_sef_request = 0.0
_sync_jobs = {}
_sync_lock = threading.Lock()



class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]


def _blob(data):
    buffer = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def dpapi_encrypt(text):
    if os.name != 'nt':
        raise RuntimeError('DPAPI je dostupan samo na Windows-u.')
    raw = text.encode('utf-8')
    in_blob, keepalive = _blob(raw)
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), 'SEF API key', None, None, None, 0x01, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_decrypt(encrypted):
    if os.name != 'nt':
        raise RuntimeError('DPAPI je dostupan samo na Windows-u.')
    in_blob, keepalive = _blob(encrypted)
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0x01, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData).decode('utf-8')
    finally:
        kernel32.LocalFree(out_blob.pbData)


def save_api_key(api_key):
    api_key = api_key.strip()
    if not api_key:
        raise RuntimeError('API ključ ne može biti prazan.')
    encrypted = dpapi_encrypt(api_key)
    with open(DPAPI_KEY_FILE, 'wb') as file:
        file.write(encrypted)


def load_api_key():
    if os.path.isfile(DPAPI_KEY_FILE):
        try:
            with open(DPAPI_KEY_FILE, 'rb') as file:
                return dpapi_decrypt(file.read()).strip()
        except Exception as exc:
            raise RuntimeError('DPAPI ključ nije moguće dešifrovati pod ovim Windows nalogom.') from exc
    return os.getenv('SEF_API_KEY', '').strip()

def db():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=30000')
    c.execute('PRAGMA journal_mode=WAL')
    return c


def pick(d, *ks):
    if not isinstance(d, dict):
        return None
    for k in ks:
        for x, v in d.items():
            if x.lower() == k.lower() and v is not None:
                return v
    return None


def find_nested(data, *names):
    wanted = {name.lower() for name in names}
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in wanted and value not in (None, ''):
                return value
        for value in data.values():
            found = find_nested(value, *names)
            if found not in (None, ''):
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_nested(value, *names)
            if found not in (None, ''):
                return found
    return None


def status_class(value):
    status = str(value or '').strip().lower()
    mapping = {
        'new': 'status-new',
        'seen': 'status-seen',
        'renotified': 'status-renotified',
        'approved': 'status-approved',
        'rejected': 'status-rejected',
        'storno': 'status-storno',
        'cancelled': 'status-storno',
        'canceled': 'status-storno'
    }
    return mapping.get(status, 'status-other')


def format_date(value):
    if value is None or value == '':
        return ''
    text = str(value).strip()
    try:
        normalized = text.replace('Z', '+00:00')
        dt = datetime.fromisoformat(normalized)
        return dt.strftime('%d/%m/%Y')
    except ValueError:
        for pattern in ('%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y'):
            try:
                return datetime.strptime(text[:10], pattern).strftime('%d/%m/%Y')
            except ValueError:
                continue
    return text


def format_number(value):
    if value is None or value == '':
        return ''
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f'{number:,.2f}'.replace(',', 'X').replace('.', ',').replace('X', '.')


app.jinja_env.filters['date_sr'] = format_date
app.jinja_env.filters['number_sr'] = format_number
app.jinja_env.filters['status_class'] = status_class


def init():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS invoices(
            invoice_id INTEGER PRIMARY KEY,
            document_number TEXT,
            document_type TEXT,
            status TEXT,
            supplier_name TEXT,
            supplier_pib TEXT,
            base_amount REAL,
            vat_amount REAL,
            total_amount REAL,
            currency TEXT,
            delivery_date TEXT,
            issue_date TEXT,
            status_changed_at TEXT,
            raw_json TEXT,
            synced_at TEXT
        )''')
        columns = {row['name'] for row in c.execute('PRAGMA table_info(invoices)').fetchall()}
        if 'issue_date' not in columns:
            c.execute('ALTER TABLE invoices ADD COLUMN issue_date TEXT')
        if 'pdf_path' not in columns:
            c.execute('ALTER TABLE invoices ADD COLUMN pdf_path TEXT')
        if 'pdf_status' not in columns:
            c.execute('ALTER TABLE invoices ADD COLUMN pdf_status TEXT')
        if 'pdf_downloaded_at' not in columns:
            c.execute('ALTER TABLE invoices ADD COLUMN pdf_downloaded_at TEXT')


def sef(path, params):
    global _last_sef_request
    key = load_api_key()
    base = os.getenv('SEF_BASE_URL', 'https://efaktura.mfin.gov.rs').rstrip('/')
    if not key or key == 'unesite_api_kljuc':
        raise RuntimeError('Podesite SEF_API_KEY u .env fajlu.')

    elapsed = time.monotonic() - _last_sef_request
    if elapsed < 0.5:
        time.sleep(0.5 - elapsed)

    r = None
    for attempt in range(5):
        _last_sef_request = time.monotonic()
        r = requests.get(
            base + path,
            headers={'ApiKey': key, 'Accept': 'application/json'},
            params=params,
            timeout=45
        )
        if r.status_code != 429:
            break
        retry_after = r.headers.get('Retry-After')
        try:
            wait_seconds = float(retry_after)
        except (TypeError, ValueError):
            wait_seconds = 2 ** (attempt + 1)
        time.sleep(wait_seconds)

    if not r.ok:
        raise RuntimeError(f'SEF HTTP {r.status_code}: {r.text[:300]}')
    return r.json()


def sef_content(path, params):
    global _last_sef_request
    key = load_api_key()
    base = os.getenv('SEF_BASE_URL', 'https://efaktura.mfin.gov.rs').rstrip('/')
    if not key or key == 'unesite_api_kljuc':
        raise RuntimeError('Podesite SEF API ključ u podešavanjima.')
    elapsed = time.monotonic() - _last_sef_request
    if elapsed < 0.5:
        time.sleep(0.5 - elapsed)
    response = None
    for attempt in range(5):
        _last_sef_request = time.monotonic()
        response = requests.get(base + path, headers={'ApiKey': key, 'Accept': 'application/xml, text/xml, */*'}, params=params, timeout=45)
        if response.status_code != 429:
            break
        try:
            wait_seconds = float(response.headers.get('Retry-After'))
        except (TypeError, ValueError):
            wait_seconds = 2 ** (attempt + 1)
        time.sleep(wait_seconds)
    if not response.ok:
        raise RuntimeError(f'SEF XML HTTP {response.status_code}: {response.text[:300]}')
    return response.content


def issue_date_from_xml(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise RuntimeError(f'SEF XML nije moguće pročitati: {exc}') from exc
    for element in root.iter():
        local_name = element.tag.split('}', 1)[-1].split(':')[-1]
        if local_name == 'IssueDate' and element.text:
            return element.text.strip()
    return None


def items(p):
    if isinstance(p, list):
        return p
    for k in ('PurchaseInvoices', 'purchaseInvoices', 'Invoices', 'invoices', 'Items', 'items'):
        if isinstance(p, dict) and isinstance(p.get(k), list):
            return p[k]
    return [p] if isinstance(p, dict) and pick(p, 'InvoiceId') else []


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            save_api_key(request.form.get('api_key', ''))
            flash('SEF API ključ je sačuvan i zaštićen Windows DPAPI mehanizmom.', 'ok')
        except Exception as exc:
            flash(str(exc), 'err')
        return redirect('/settings')
    return render_template('settings.html', key_saved=os.path.isfile(DPAPI_KEY_FILE))


@app.post('/settings/delete-key')
def delete_key():
    try:
        if os.path.isfile(DPAPI_KEY_FILE):
            os.remove(DPAPI_KEY_FILE)
        flash('Šifrovani API ključ je uklonjen.', 'ok')
    except OSError as exc:
        flash(f'Ključ nije uklonjen: {exc}', 'err')
    return redirect('/settings')


def status_counts():
    with db() as c:
        rows = c.execute("SELECT LOWER(COALESCE(status,'')) s, COUNT(*) n FROM invoices GROUP BY LOWER(COALESCE(status,''))").fetchall()
    by_status = {r['s']: r['n'] for r in rows}
    return {
        'total': sum(by_status.values()),
        'approved': by_status.get('approved', 0),
        'rejected': by_status.get('rejected', 0),
        'new': by_status.get('new', 0),
        'seen': by_status.get('seen', 0),
        'storno': by_status.get('storno', 0),
    }


@app.route('/')
def index():
    q = request.args.get('q', '')
    status = request.args.get('status', '')
    sql = 'SELECT * FROM invoices WHERE 1=1'
    args = []
    if q:
        sql += ' AND (document_number LIKE ? OR supplier_name LIKE ? OR supplier_pib LIKE ?)'
        args += [f'%{q}%'] * 3
    if status:
        sql += ' AND status=?'
        args.append(status)
    with db() as c:
        rows = c.execute(sql + ' ORDER BY delivery_date DESC, invoice_id DESC', args).fetchall()
    return render_template('index.html', rows=rows, q=q, status=status, counts=status_counts())


def run_sync(job_id, form):
    try:
        date_from_display = form['date_from'].strip()
        date_to_display = form['date_to'].strip()
        try:
            date_from = datetime.strptime(date_from_display, '%d/%m/%Y').strftime('%Y-%m-%d')
            date_to = datetime.strptime(date_to_display, '%d/%m/%Y').strftime('%Y-%m-%d')
        except ValueError:
            raise RuntimeError('Datume unesite u formatu DD/MM/YYYY.')
        status = form.get('status') or None
        params = {'dateFrom': date_from, 'dateTo': date_to}
        if status:
            params['status'] = status
        with _sync_lock: _sync_jobs[job_id].update(state='running',percent=2,message='Preuzimanje spiska faktura...')
        data = items(sef('/api/publicApi/purchase-invoice/overview', params))
        total=len(data); saved = 0
        with _sync_lock: _sync_jobs[job_id].update(total=total,percent=5,message=f'Pronađeno faktura: {total}')
        with db() as c:
            for index, overview in enumerate(data,1):
                with _sync_lock: _sync_jobs[job_id].update(current=index,percent=5+round((index-1)/max(total,1)*90),message=f'Obrada fakture {index} od {total}: detalji i datum fakture...')
                invoice_id = pick(overview, 'InvoiceId')
                if invoice_id is None:
                    continue
                detail = sef('/api/publicApi/purchase-invoice', {'invoiceId': invoice_id})
                detail = detail[0] if isinstance(detail, list) and detail else detail
                invoice_xml = sef_content('/api/publicApi/purchase-invoice/xml', {'invoiceId': invoice_id})
                xml_issue_date = issue_date_from_xml(invoice_xml)
                values = (
                    int(invoice_id),
                    pick(overview, 'DocumentNumber', 'InvoiceNumber'),
                    pick(overview, 'DocumentType', 'InvoiceType'),
                    pick(detail, 'Status') or pick(overview, 'Status'),
                    pick(overview, 'SupplierName', 'Sender'),
                    pick(overview, 'SupplierVatRegistrationNumber'),
                    pick(overview, 'SumWithoutVat') or 0,
                    pick(overview, 'VatAmount', 'VatSum') or 0,
                    pick(overview, 'Amount', 'SumWithVat') or 0,
                    pick(overview, 'Currency', 'CurrencyName'),
                    pick(overview, 'DeliveryDate'),
                    xml_issue_date or find_nested(detail, 'IssueDate', 'InvoiceIssueDate', 'DocumentIssueDate') or find_nested(overview, 'IssueDate', 'InvoiceIssueDate', 'DocumentIssueDate'),
                    pick(detail, 'LastModifiedUtc'),
                    json.dumps({'overview': overview, 'detail': detail}, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat()
                )
                c.execute('''INSERT INTO invoices (invoice_id,document_number,document_type,status,supplier_name,supplier_pib,base_amount,vat_amount,total_amount,currency,delivery_date,issue_date,status_changed_at,raw_json,synced_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(invoice_id) DO UPDATE SET
                    document_number=excluded.document_number,
                    document_type=excluded.document_type,
                    status=excluded.status,
                    supplier_name=excluded.supplier_name,
                    supplier_pib=excluded.supplier_pib,
                    base_amount=excluded.base_amount,
                    vat_amount=excluded.vat_amount,
                    total_amount=excluded.total_amount,
                    currency=excluded.currency,
                    delivery_date=excluded.delivery_date,
                    issue_date=excluded.issue_date,
                    status_changed_at=excluded.status_changed_at,
                    raw_json=excluded.raw_json,
                    synced_at=excluded.synced_at''', values)
                saved += 1
                c.commit()
                if form.get('download_pdfs') == '1':
                    with _sync_lock:
                        _sync_jobs[job_id].update(message=f'Preuzimanje PDF-a {index} od {total}...')
                    try:
                        fetch_and_store_pdf(invoice_id, pick(overview, 'DocumentNumber', 'InvoiceNumber'), pick(overview, 'DeliveryDate'))
                    except Exception:
                        with db() as pdf_db:
                            pdf_db.execute("UPDATE invoices SET pdf_status='error' WHERE invoice_id=?", (invoice_id,))
                with _sync_lock: _sync_jobs[job_id].update(saved=saved,percent=5+round(index/max(total,1)*90))
        with _sync_lock: _sync_jobs[job_id].update(state='done',percent=100,saved=saved,message=f'Sinhronizacija završena. Sačuvano: {saved} faktura.')
    except Exception as e:
        with _sync_lock: _sync_jobs[job_id].update(state='error',message=str(e))




@app.post('/sync/start')
def sync_start():
    with _sync_lock:
        if any(x.get('state') in ('queued','running') for x in _sync_jobs.values()): return jsonify(error='Sinhronizacija je već u toku.'),409
        jid=uuid.uuid4().hex; _sync_jobs[jid]={'state':'queued','percent':0,'message':'Pokretanje...','current':0,'total':0,'saved':0}
    form=request.form.to_dict(); threading.Thread(target=run_sync,args=(jid,form),daemon=True).start()
    return jsonify(job_id=jid)

@app.get('/sync/progress/<jid>')
def sync_progress(jid):
    with _sync_lock:
        if jid not in _sync_jobs: return jsonify(error='Proces nije pronađen.'),404
        return jsonify(_sync_jobs[jid])

def safe_filename(value):
    text = re.sub(r'[^A-Za-z0-9._-]+', '_', str(value or 'faktura')).strip('._')
    return text[:100] or 'faktura'


def fetch_and_store_pdf(invoice_id, document_number=None, delivery_date=None):
    content = sef_content('/api/publicApi/purchase-invoice/pdf', {'invoiceId': invoice_id})
    # SEF može prvo vratiti JSON poruku da je generisanje inicirano.
    stripped = content.lstrip()
    if not stripped.startswith(b'%PDF-'):
        try:
            message = json.loads(content.decode('utf-8')).get('message', 'Generisanje PDF-a je pokrenuto.')
        except Exception:
            message = 'SEF još nije vratio PDF dokument.'
        with db() as c:
            c.execute("UPDATE invoices SET pdf_status='generation_started' WHERE invoice_id=?", (invoice_id,))
        return None, message
    year, month = 'unknown', 'unknown'
    if delivery_date:
        parts = str(delivery_date)[:10].split('-')
        if len(parts) == 3:
            year, month = parts[0], parts[1]
    folder = os.path.join(PDF_DIR, year, month)
    os.makedirs(folder, exist_ok=True)
    filename = f"{invoice_id}_{safe_filename(document_number)}.pdf"
    full_path = os.path.join(folder, filename)
    with open(full_path, 'wb') as file:
        file.write(content)
    relative = os.path.relpath(full_path, BASE_DIR)
    with db() as c:
        c.execute("UPDATE invoices SET pdf_path=?, pdf_status='downloaded', pdf_downloaded_at=? WHERE invoice_id=?",
                  (relative, datetime.now(timezone.utc).isoformat(), invoice_id))
    return full_path, 'PDF je preuzet.'


@app.get('/invoice/<int:invoice_id>/pdf')
def invoice_pdf(invoice_id):
    with db() as c:
        row = c.execute('SELECT * FROM invoices WHERE invoice_id=?', (invoice_id,)).fetchone()
    if not row:
        return jsonify(error='Faktura nije pronađena.'), 404
    if row['pdf_path']:
        existing = os.path.join(BASE_DIR, row['pdf_path'])
        if os.path.isfile(existing):
            return send_file(existing, mimetype='application/pdf', as_attachment=False, download_name=os.path.basename(existing))
    try:
        full_path, message = fetch_and_store_pdf(invoice_id, row['document_number'], row['delivery_date'])
        if full_path:
            return send_file(full_path, mimetype='application/pdf', as_attachment=False, download_name=os.path.basename(full_path))
        return jsonify(status='generation_started', message=message), 202
    except Exception as exc:
        with db() as c:
            c.execute("UPDATE invoices SET pdf_status='error' WHERE invoice_id=?", (invoice_id,))
        return jsonify(error=str(exc)), 500


@app.get('/export.csv')
def export():
    with db() as c:
        rows = c.execute('SELECT * FROM invoices ORDER BY delivery_date DESC').fetchall()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['SEF ID', 'Broj', 'Tip', 'Status', 'Dobavljač', 'PIB', 'Osnovica', 'PDV', 'Ukupno', 'Valuta', 'Datum fakture', 'Datum prometa', 'Poslednja promena'])
    for r in rows:
        writer.writerow([
            r['invoice_id'], r['document_number'], r['document_type'], r['status'],
            r['supplier_name'], r['supplier_pib'], format_number(r['base_amount']),
            format_number(r['vat_amount']), format_number(r['total_amount']), r['currency'],
            format_date(r['issue_date']), format_date(r['delivery_date']), format_date(r['status_changed_at'])
        ])
    return Response('\ufeff' + output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=sef_fakture.csv'})


init()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
