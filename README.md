# Implementacija polinomske zaveze KZG in Verklovih dreves
Repozitorij s praktičnim izdelkom moje diplomske naloge z naslovom **Polinomske zaveze: kriptografsko ozadje in praktične aplikacije**. Repozitorij vsebuje implementacijo polinomske zaveze KZG (datoteka `kzg.py`), Merklovega drevesa (datoteka `merkle_tree.py`) in Verklovega drevesa (datoteka `verkle_tree.py`). V datoteki `analysis.ipynb` je prikazno osnovno delovanje polinomske zaveze, analiza velikosti dokazov in časov preverjanja dokaza Merklovega in Verklovega drevesa.

## Zagon

Za zagon programov je potrebno imeti nameščen Python verzije 3.11.9 (modul `py-ecc` ne deluje dobro z verzijami Pythona naprej od vključno 3.12).

Za namestitev ustreznih modulov poženemo:
```
pip install -r requirements.txt
```