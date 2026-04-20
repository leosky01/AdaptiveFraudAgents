# Data Schema – Reply Mirror (Fraud Detection)

## Levels
- **The Truman Show**: 3 citizens, 80 txns (smallest)
- **Brave New World**: 7 citizens, 522 txns (medium)
- **Deus Ex**: 12 citizens, 2017 txns + 48 audio files (largest)

### transactions.csv
| Column | Type | Description |
|--------|------|-------------|
| transaction_id | UUID | Unique transaction identifier |
| sender_id | string | Citizen ID (XXXX-XXXX-XXX-XXX-X) or entity (EMP*, ABIT*, etc.) |
| recipient_id | string | Citizen ID or entity |
| transaction_type | string | transfer, e-commerce, in-person payment, direct debit, withdrawal |
| amount | float | Transaction amount |
| location | string | Only for in-person payments (City - Venue Name) |
| payment_method | string | debit card, mobile device/phone, smartwatch, Google Pay, PayPal |
| sender_iban | string | Sender IBAN |
| recipient_iban | string | Recipient IBAN |
| balance_after | float | Sender balance after transaction |
| description | string | Optional description (Salary, Rent, etc.) |
| timestamp | ISO datetime | When transaction occurred |

### users.json
```json
[{
  "first_name": "Alain",
  "last_name": "Regnier",
  "birth_year": 2047,
  "salary": 34100,
  "job": "Office Clerk",
  "iban": "FR85H4824371990132980420818",
  "residence": { "city": "Audincourt", "lat": "47.4836", "lng": "6.8403" },
  "description": "... contains phishing susceptibility info ..."
}]
```

### locations.json (GPS pings)
```json
[{
  "biotag": "RGNR-LNAA-7FF-AUD-0",
  "timestamp": "2087-01-01T19:46:18",
  "lat": 47.4692,
  "lng": 6.8217,
  "city": "Audincourt"
}]
```

### sms.json
Contains SMS messages — mix of legitimate (city notifications) and **phishing** (fake PayPal/Amazon/Uber with typo-domains like `paypa1`, `amaz0n`, `ub3r`).

### mails.json
Contains email threads — mix of legitimate and **phishing** emails (from domains like `paypa1-secure.net`).

### audio/ (Deus Ex only)
MP3 files named `YYYYMMDD_HHMMSS-person_name.mp3`. Phone calls requiring transcription.

## Key Entity Patterns
- **Citizens**: `XXXX-XXXX-XXX-XXX-X` (e.g. RGNR-LNAA-7FF-AUD-0)
- **Employers**: `EMP*` (salary payments)
- **Landlords**: `ABIT*`, `RES*`, `HOME*`, `DOM*`, `PROP*`, `RENT*` (rent)
- **Merchants**: `MKT*`, `PAY*`, `SHP*`, `RET*` (e-commerce)
- **Services**: `ACC*`, `CMP*`, `BIL*`, `SUB*`, `SRV*` (direct debits)
