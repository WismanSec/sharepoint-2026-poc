# Example artifact — machine-key disclosure, redacted

Request: 2x `POST /_trust/default.aspx` (preamble + main). Response carried, sentinel-wrapped:

```
<<<KD:<VALIDATIONKEY_REDACTED_64hex>|HMACSHA256|<DECRYPTIONKEY_REDACTED_64hex>|Auto|Framework45:KD>>>
```

SIEM in the same window: **0 process_create, 0 Defender events, no beacon.** In-process in w3wp.
Only artifact = the /_trust POST + anomalous response. → rotate machine keys to revoke.
