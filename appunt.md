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

La "perdita" delle funzioni importate non avviane anche nei binari posix. Potrebbe non essere quello il problema dei binari a questo punto il problema è legato alla gestione dei binari windows. 
Nel file [elf.rs](bias-core/src/loader/elf.rs) vine chiamata una funzione implementata all'interno di [mod.rs](bias-core/src/project/mod.rs). Questa funzione restituisce una symtable contenente tutti i nomi di funzione presenti nel binario. Ha senso che non vi sia questa funzione in [pe.rs](bias-core/src/loader/pe.rs). 

### File modificati dall'ultimo commit

- [mod.rs](bias-core/src/project/mod.rs) 
- [pe.rs](bias-core/src/loader/pe.rs)
- [table.rs](bias-core/src/kb/table.rs)

Prbabili file da modificare : 

- [functions.rs](bias-core/src/kb/function.rs)

Dopo aver controllato tutti i file sopra elencati, aggiunto opportune stringhe di debug e aver confrontato il funzionamento anche con binari e regole posix (che fosse certo funzionassero), sembra che in questi file non vi siano metodo implementazioni che interagisacno in alun modo con lo scope call. 
Penso sia utile guardare l'implemntazione dello scpoe call. 

#### Digressione sul file [icfg.rs](bias-core/src/cfg/icfg.rs) e implementazione di relocation in [pe.rs](bias-core/src/loader/pe.rs)
Sembra che possa tornare utile provare a pulire e rigenerare l'icfg dato che viene generato prima che vengano modificati gli indirizzi di memoria delle funzioni importate. Un'altra idea sembra poter essere quella di implementare la relocation degli indirizzi delle funzioni (strada che sembra poco praticabile).


## Scope call

Implementazione in [scope.rs](bias-vulhunt-engine/src/lua/scope.rs).

