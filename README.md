# SEF ulazne fakture v2

1. `python -m venv .venv`
2. `./.venv/Scripts/python.exe -m pip install -r requirements.txt`
3. Kopirati `.env.example` u `.env` i uneti API ključ.
4. `./.venv/Scripts/python.exe app.py`

Izmene u v2:
- datumi se prikazuju i izvoze kao DD/MM/YYYY;
- ISO datum poslednje promene prikazuje se bez vremena;
- iznosi se prikazuju i izvoze kao 1.234,56;
- uključeni truststore i ograničenje brzine zahteva prema SEF-u.

SQLite čuva originalne vrednosti; lokalizacija se primenjuje samo pri prikazu i CSV izvozu.

Izmene u v3:
- dodata kolona Datum fakture (IssueDate);
- automatska migracija postojeće SQLite baze;
- bojenje redova po statusu;
- Rejected i Storno su posebno naglašeni.

Izmene u v5 - DPAPI:
- API ključ se unosi na stranici Podešavanja API ključa;
- ključ se čuva šifrovan u sef_api_key.dat pomoću Windows DPAPI CurrentUser zaštite;
- plaintext ključ se ne prikazuje u interfejsu;
- postojeći SEF_API_KEY iz .env ostaje samo fallback dok DPAPI ključ nije sačuvan;
- nakon uspešnog DPAPI čuvanja preporučuje se uklanjanje SEF_API_KEY reda iz .env.
