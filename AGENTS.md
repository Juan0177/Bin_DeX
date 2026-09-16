# Bin_DeX Agent Guidelines

## Obiettivo del Progetto
Bin_DeX è uno strumento di ispezione e decodifica di dump binari raw (es. file info dump), composto da:
1. **Frontend Web (`index.html`, `app.js`, `styles.css`)**: visualizzatore locale in-browser con hex viewer, navigazione per offset, estrazione di stringhe leggibili e anteprima/esportazione JSON.
2. **Backend / CLI Python (`binary_dump_parser.py`)**: parser a riga di comando che gestisce decompressione (gzip/zlib), deserializzazione automatica (MessagePack, CBOR, BSON) ed esportazione strutturata.

## Linee Guida di Sviluppo
- **Sincronia Funzionale**: Le funzionalità supportate dal parser Python (es. formati di decompressione, rilevamento stringhe, deserializzazione) dovrebbero avere una controparte fedele nel visualizzatore web in browser ove possibile (usando librerie client-side come `pako`, `msgpack-lite`, `cbor-js`).
- **Prestazioni con File Grandi**: Evitare di creare migliaia di nodi DOM tutti insieme. Se si caricano file binari superiori a qualche decina di KB, utilizzare paginazione, virtual scrolling o chunking.
- **UI & UX**: Mantenere il tema scuro coerente con Bootstrap dark e la palette di `styles.css`.
- **Dipendenze Python**: I pacchetti opzionali (`msgpack`, `cbor2`, `pymongo`) sono già configurati nell'ambiente locale e nel virtual environment `.venv`.

