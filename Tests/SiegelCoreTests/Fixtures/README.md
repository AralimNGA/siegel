# Feste Testvektoren (SPEC §10) – nie ändern

Diese Werte und die Dateien `v1_beispiel.siegel` und `v2_beispiel.siegel` sind eingefroren. Jede künftige
Siegel-Version muss sie weiterhin bestehen bzw. öffnen können (über beide Wege). Die Tests stehen in
`Tests/SiegelCoreTests/Kern/KernTestvektorTests.swift`, `KernEchteProfileTests.swift`, `KernFixtureV2Tests.swift`,
`KernBeispielDateiV2.swift`, `KernCardCodeTests.swift` (Suiten „QR-Schlüsselkarte“ und „Mehrfaktor-Ableitung“) und
`KernShamirTests.swift`.

## (a) Notfallschlüssel-Ableitung

Eingabe: `R = 00 01 02 … 1f` (32 Byte), `vaultID = a0 a1 … af` (16 Byte).

| Wert | Ergebnis |
|---|---|
| `SHA3-256(pkM)` | `07d2a982d901e86a75c81c97704b1a66571c8ae4664039ec55e286cbbac206f2` |
| `pkX` | `157638f533039b946e64edc0135d67ad5c805d89cc0530bec075e14266213107` |
| Notfallcode | `000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FRAC8` |
| Kit-Kennung | `HKEH-KJPJ` (zusätzlich festgehalten, unabhängig nachgerechnet) |

## (b) Beispieldatei `v1_beispiel.siegel`

Erzeugt am 16.10.2026 vom Kern v3.1 (damals `KernFixtureErzeugungTests.swift`, Umgebungsvariable
`SIEGEL_FIXTURE_ZIEL`). Der heutige Kern schreibt nur noch Format v2 und kann diese Datei nicht neu erzeugen; sie
ist der Beleg, dass v1 lesbar bleibt. Nur erfundene Einträge. Seit v4 wird sie beim ersten Speichern zu v2
(vorher angeheftete Sicherung `vor-migration-v1`, bytegleich); Passwort und Notfallcode gelten weiter.

| | |
|---|---|
| Formatversion | 1 |
| KDF | Argon2id, m = 256 MiB (268 435 456 Byte), t = 3 |
| Master-Passwort | `7:etFa_0+Isq#jQ0oeTb8nWKFM*9` (zufällig, 28 Zeichen) |
| Notfallcode | `NHZZD-BYYYZ-ZYMNR-W0S31-BZK7X-0S860-H7KZ4-YEBE7-7JNMC-G8367-YZ2N0` |
| Kit-Kennung | `3Q0A-CCCJ` |
| vaultID | `06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2` |
| Generation | 6 |
| Grösse | 19 865 Byte |
| SHA-256 der Datei | `ee16046c2a50bd47250a276d62f5aa63e60f9aee231da379d9ad44904b43aa13` |
| Notfallkit bestätigt | ja (`recoveryConfirmedAt` gesetzt) |

Inhalt (3 Einträge):

1. „Bibliothek Bern“, Benutzer `leserin.muster`, Passwort `Buecher-Regal-42!`, `https://bibliothek.example.ch`,
   Notiz „Ausweisnummer steht auf der Karte.“
2. „Velo-Club“, Benutzer `velofahrer`, Passwort `Kette+Sattel-77` (Verlauf: `Rad&Weg-2026`), `velo.example.ch`
3. „Notiz ohne Website“, ohne Benutzer/Passwort/Website, Notiz mit Zeilenumbruch, Umlauten und «»

## (c) KEK_rec der Beispieldatei

`KEK_rec` für die in der Datei fixierten `(ctM, ctX)` mit dem Notfallcode aus (b):

`c406914254c7efdd3c75b9510e779fa6553b3776c0ffa7c2c988c4259ce3f9d8`

## (d) Beispieldatei `v2_beispiel.siegel` (Stufe 5 „Festung“)

Erzeugt am 17.10.2026 mit `KernFixtureErzeugungTests.swift` (nur von Hand, Umgebungsvariable
`SIEGEL_FIXTURE_V2_ZIEL`) über die öffentliche Schnittstelle: `create` → Kit bestätigen → Einträge →
`prepareRecovery(…, scheme: .shamir2of3)` → `changeSecurityLevel(to: .festung, …)` mit den festen Faktoren unten →
Passwortwechsel im Eintrag „Velo-Club“. Nur erfundene Einträge. Alle Werte unten wurden unabhängig mit Python
(`hashlib`/`hmac` für SHA3/HKDF, libsodium per `ctypes` für Argon2id und XChaCha20-Poly1305) nachgerechnet;
dabei liessen sich Prüfsumme, Kopf, pwSlot und Inhalt öffnen.

| | |
|---|---|
| Formatversion | 2, Stufe 5 (factorMask = 7, recoveryScheme = 2) |
| KDF | Argon2id, m = 256 MiB (268 435 456 Byte), t = 3 |
| Master-Passwort | `6Bn__S?ZC37umQe_9A!^6K!9_nNk` (zufällig, 28 Zeichen) |
| Teil 1 von 3 | `04A6Z-0CJEQ-E7T55-1KVCB-7K5WQ-E3V63-2BGH5-P3KM3-RQF38-40TW4-Y1XQ2-N` |
| Teil 2 von 3 | `08F19-MM81R-FAMDM-D44N1-N36HJ-M1QKG-CG8GG-G7JF2-Q81KE-637EJ-35EMW-0` |
| Teil 3 von 3 | `0CC3V-RVQ4Y-MYEA3-0QP6Q-TH83H-XZKYW-YS0G3-X8F9M-CS43D-TAC0W-CSJTH-6` |
| Kit-Kennung | `2RMY-XAAA` |
| vaultID | `D4F9B640-FECB-4BAB-A72D-28DBA1D1636D` |
| Generation | 7 |
| Grösse | 19 985 Byte (Kopf 1773 = 1709 + 64 Byte Credential) |
| SHA-256 der Datei | `53c78ad55d5126ae72b9f02595104238b4d3c46359006c654713f27e6c82dff5` |
| Notfallkit bestätigt | ja |
| Faktor Secure Enclave (Hex) | `1111111111111111111111111111111111111111111111111111111111111111` |
| Faktor Karte (Hex) | `2222222222222222222222222222222222222222222222222222222222222222` |
| Faktor FIDO2 (Hex) | `3333333333333333333333333333333333333333333333333333333333333333` |

Feste Faktor-Werte (roh, wie sie das Hardware-Modul liefert):

| Faktor | Wert |
|---|---|
| ECDH_SE (Secure Enclave, öffnen) | `11` × 32, seKeyID `11111111-2222-4333-8444-555555555555` |
| q (QR-Karte) | `22` × 32 → cardTag `b2fdc001` |
| hmac-secret-Ausgabe (FIDO2, öffnen) | `33` × 32, credentialID `44` × 64, Salz `55` × 32 |
| Eintrags-SE-Schlüssel | keyID `66666666-7777-4888-8999-AAAAAAAAAAAA`, öffentlicher Teil von P-256-Skalar `88` × 32 |
| FIDO2 für Einträge | entrySalt `66` × 32, Ausgabe `77` × 32 |

Inhalt: dieselben drei Einträge wie (b), zusätzlich TOTP im „Velo-Club“
(`otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club`); alle drei Faktoren für Einträge
eingerichtet.

## (e) Mehrfaktor-Ableitung (KAT) der Beispieldatei v2

| Wert | Ergebnis |
|---|---|
| kdfSalt | `e1a44dd212cc4e593c56f3c2aeef12c1` |
| p = Argon2id(pw) | `0aba515de29ce382121b9355eb693daebc778d6378affdf4719f2c25f618b2d0` |
| e = HKDF(ECDH_SE, vaultID, "Siegel v2 factor secure-enclave") | `8fbcf78df09ce432ff8b693dd8c8dce0aba9c424280e7a17763677aa2fd776d5` |
| c = HKDF(q, vaultID, "Siegel v2 factor card") | `d57682004bbd6e767859be1a1306e9f8499a829a7184cf88d57560685b1c961d` |
| y = HKDF(hmacOut, vaultID, "Siegel v2 factor fido2") | `89f8f8f3c3d18b6756605cda1a1860df54afaa61b5d11413837e58a613a1c4c6` |
| KEK_pw = HKDF(p ‖ e ‖ c ‖ y, kdfSalt, "Siegel v2 kek" ‖ 07) | `c15d504d2f670fbf21d5ba74fc2395139ef5aafc826d87bae6bac24c5f096c89` |

## (f) Shamir 2 aus 3 und QR-Karte

- Shamir: `R = 00 01 … 1f`, `a = a0 a1 … bf` → Teile
  `06GA1-850M2-GA185-0M2GA-1850M-2GA18-50M2G-A1850-M2GA1-850M2-GA1GP-B`,
  `09DNG-QAYAX-A52MJ-3812M-CKTC9-556PT-3DDSK-P8RB2-EDR7A-XKZFH-WQNY6-N`,
  `0FXZK-ZZXYF-RZFXF-BX7QY-VRZ1W-ZJXQP-EZVQ9-X3NYN-SF4WZ-KE3R7-3WATN-T`.
- QR-Karte: `q = 00 01 … 1f` → `SIEGELKARTE1:000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFQVT8`;
  Kennung für `vaultID = a0 … af`: `08b8de3f`.

