Questo script è il risultato pratico del mio lavoro di tesi triennale in Informatica.

Sviluppato in Python per l'ambiente Ghidra, lo script provvede a rilevare in maniera automatica il Reflective PE Loader all'interno del ransomware WannaCry. Invece di basarsi su semplici firme, il tool sfrutta un'analisi euristica direttamente sul P-Code (l'Intermediate Representation di Ghidra).

Uno degli obiettivi primari dello script è l'approccio malware-agnostic: la logica di tracciamento a ritroso (Backtracing) è stata studiata per poter essere impiegata teoricamente anche su altri malware complessi che adottano strategie di offuscamento e caricamento similari a quelle di WannaCry.

Trattandosi di uno sviluppo accademico, il codice rappresenta un Proof of Concept (PoC) puramente sperimentale e dimostrativo, volto a esplorare le potenzialità dell'analisi statica avanzata per supportare i processi di Reverse Engineering.
