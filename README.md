# Saboss Scan

Saboss Scan är en första fungerande MVP för en enkel domän- och webbplatssäkerhetsscanner.

Den kontrollerar:

- SSL/TLS-certifikat
- HTTP Security Headers
- DNS-records
- SPF, DMARC och en enkel DKIM-best-effort
- Security Score
- Rekommendationer på enkel svenska

> Använd endast scannern på domäner du äger eller har tillstånd att kontrollera.

## 1. Installera

Öppna projektet i VS Code och kör:

```bash
python -m venv .venv
```

Aktivera virtual environment:

Windows PowerShell:

```bash
.venv\Scripts\Activate.ps1
```

Mac/Linux:

```bash
source .venv/bin/activate
```

Installera paketen:

```bash
pip install -r requirements.txt
```

## 2. Kör en scan

```bash
python main.py example.com
```

Spara rapport som JSON:

```bash
python main.py example.com --json report.json
```

## 3. Lägg upp på GitHub

```bash
git init
git add .
git commit -m "first version of saboss scan"
git branch -M main
git remote add origin https://github.com/DITT-NAMN/saboss-scan.git
git push -u origin main
```

## 4. Projektstruktur

```text
saboss-scan/
├── main.py
├── requirements.txt
├── README.md
├── saboss_scan/
│   ├── scanner.py
│   ├── ssl_checker.py
│   ├── headers_checker.py
│   ├── dns_checker.py
│   ├── scoring.py
│   ├── recommendations.py
│   └── utils.py
└── tests/
    └── test_scoring.py
```

## 5. Viktiga filer

### main.py
Startfilen. Tar emot domänen från terminalen och skriver ut resultatet.

### scanner.py
Kör hela scannen genom att anropa SSL, headers, DNS, scoring och recommendations.

### ssl_checker.py
Ansluter till port 443 och läser certifikatet.

### headers_checker.py
Hämtar webbplatsen och kontrollerar viktiga säkerhetsheaders.

### dns_checker.py
Kontrollerar A, AAAA, MX, TXT, SPF, DMARC och vanliga DKIM-selectors.

### scoring.py
Räknar ut Saboss Security Score.

### recommendations.py
Skapar enkla rekommendationer baserat på problemen som hittades.

## 6. Testa koden

```bash
pytest
```
