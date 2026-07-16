file di windows

- [`/bias-core/src/loader/pe.rs`](/bias-core/src/loader/pe.rs)
  Questo file sembra definire l'oggetto `PELoader`. Questo oggetto sembra occuparsi del caricamento e del parsing del binario PE. (*Questo file era già presente nella repo originale*).
  ```rust
        bytes.extend_from_slice((0x31c0_u16).to_be_bytes().as_ref()); // XOR EAX, EAX
        bytes.extend_from_slice((0xc3_u8).to_be_bytes().as_ref()); // RET  
  ```
  Nel file è presente questa stringa di codice che permette di passare ad un'altra funzione importata (per ogni nuova funzione bisogna cambiare il contenuto di `extend_from_slice(...)`). Bisonga generalizzare il calcolo del address globale tramite adress relativo.
- [`bias/src/platform/windows/mod.rs`](bias/src/platform/windows/mod.rs)
  Questo file pare raccolga le caratteristiche legate al binario, sembra anche in qualche modo legato al file `.json` di output. (*Questo file era già presente nella repo originale ma è stato spostato e rinominato, da `bias/src/platform/windows.rs`*)

- [`bias/src/platform/windows/analysis.rs`](bias/src/platform/windows/analysis.rs)
  Questo file sembra occuparsi effettivamente dell'analisi del binario, andando anche ad accedere alla cartella dei `bias-data`. (*Questo file è stato ricavato copiando e incollando dal codice dell'analogo file nella cartella `bias/src/paltfrom/posix` e modificandolo opportunamente*).

- [`bias/src/loader/meta/windows.rs`](bias/src/loader/meta/windows.rs)
  Questo file sembra popolare il `.json` di output con i dati raccolti precedentemente. (*Questo file era già presente nella repo originale*).

- [`bias-vulhunt-engine/src/analysis/windows.rs`](bias/src/loader/meta/windows.rs)

 **Aggiunte righe di debug al file**

  ##### Questa parte di codice implementa `VulHuntWindowsAnalyser`, che effettua l'analisi sul binario. (*Questo file è stato aggiunto partendo da [`bias-vulhunt-engine/src/analysis/posix.rs`](bias-vulhunt-engine/src/analysis/posix.rs)*). 

- [`bias-vulhunt-engine/src/lua/project/decompiler.rs`](bias-vulhunt-engine/src/lua/project/decompiler.rs)
  Parte di codice relativa al decompilatore



- [`bias-core/src/windows/test.rs`](bias-core/src/windows/test.rs)
  Creare l'algoritmo che riesca a gestire le import-table e a calcolare l'indirizzo assoluto della chiamata dato l'indirizzo relativo, per permettere al framework di capire che stiamo lavorando con delle chiamate a funzione e poter utilizzare lo scope call per i binari windows.  


---

Le funzioni importate possono essere viste dal tool tramite una particolare libreria rust chiamata goblin che parsa i file binari.


---
Logica che si occupa di gestire gli `scope:calls`:
- [`bias-vulhunt-engine/src/lua/query.rs`](bias-vulhunt-engine/src/lua/query.rs)
- [`bias-vulhunt-engine/src/lua/scope.rs`](bias-vulhunt-engine/src/lua/scope.rs)

Pare che le funzioni vengano riconosciute da vulhunt ma questo essere risonosciute non sia persistente all'interno del programma. Pare ci sia una mappa che tiene traccia delle funzioni presenti e del loro address, ma pare anche che tale mappa venga sovrascritta durante il controllo. Queste informazioni sono relative al fatto che nella funzione `get_points` del file [`/home/prescigno/vulhunt-thesis/bias-core/src/kb/table.rs`](bias-core/src/kb/table.rs)

Le strutture dati che gestiscono questa tabella sono complesse: 
- Partendo da `MPointTable`, è una struttura che associa una hash map a una `MTable`.
- `MTable` è composto da un `Slab` (una sruttura dati che pare fare da preallocatore della memoria per un singolo tipo di dato).

La "perdita" delle funzioni importate avviane anche nei binari posix. Potrebbe non essere quello il problema dei binari a questo punto il problema potrebbe essere legato alla gestione dei binari windows. 