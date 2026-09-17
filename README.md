# Hardware Trojan Detection on Gate-Level Netlists


This repository contains our solution for the **[ICCAD Contest 2025 (Problem A: Hardware Trojan Detection on Gate-Level Netlist)](https://www.iccad-contest.org/2025/)**. The project provides an automated pipeline designed to analyze Verilog netlists, determine whether a Hardware Trojan is present, and pinpoint the specific gate instances associated with the detected Trojan.

More details about the procedures can be found in the paper below.

* N. N. Tehrani, A. Davoodi, and R. O. Topaloglu, “Demystifying gate-level localization of rtl trojans,” 2026. [Online]. Available:
https://arxiv.org/abs/2609.17922

---

Hardware Trojans pose significant security risks to integrated circuit (IC) designs. Problem A of the ICCAD 2025 Contest focuses on detecting stealthy Hardware Trojans inserted into flattened gate-level Verilog netlists.

The primary objective is twofold:
1. **Classification:** Identify whether a netlist contains a Hardware Trojan (`TROJANED` vs. `NO_TROJAN`).
2. **Localization:** If a Trojan exists, accurately identify and list all gate instances that constitute the Trojan structure.

### Contest Scoring Rule
The evaluation metric balances both detection correctness and localization precision:
* **Base Score:** Awarded for correctly classifying netlists as Trojan-free or Trojan-infected.
* **Localization Score:** Calculated using the F1-Score based on True Positives (TP), False Positives (FP), and False Negatives (FN) of the identified Trojan gates:

  $$F1 = 2 \times \frac{Precision \times Recall}{Precision + Recall}$$

* **Final Score:** Sum of base scores and localization F1-scores across all test benchmarks.

---

## Repository Structure

* `data/`: Benchmark netlists and ground-truth result files used for local evaluation.
* `detection_codes/`: Python modules (`does_have_trojan0.py` to `does_have_trojan8_and_9.py`) containing the specific Trojan detection patterns and logic.
* `utils/`: Netlist parsing and helper utility functions.
* `main_decider.py`: Official contest execution script.
* `main_evaluator.ipynb`: Interactive Jupyter notebook for batch testing, debugging, and calculating the final contest score on labeled datasets.
* `README.md`: Project documentation.

---

## How to Run

### 1. Contest Execution Format (`main_decider.py`)

`main_decider.py` complies with the standard submission format required by the ICCAD contest. It takes an input Verilog netlist file and generates an output text file containing the detection results.

**Usage:**
```bash
python main_decider.py -netlist <path_to_netlist.v> -output <path_to_output_result.txt>
```


### 2. Testing & Score Evaluation (`main_evaluator.ipynb`)

main_evaluator.ipynb is designed for offline development, debugging, and evaluation on labeled benchmark datasets (where ground-truth Trojan gate lists are available).

Features:
* Runs detection across test datasets in batch mode.
* Compares predicted Trojan gates against ground-truth labels (result*.txt).
* Computes performance metrics including $\text{Precision}$, $\text{Recall}$, $\text{TPR}$, $\text{FPR}$, and $\text{F}_1$-Score per benchmark.
* Outputs the aggregated Final Contest Score according to official competition evaluation rules.

## Citation

If you use this repository, detection algorithms, or dataset structure in your research, please cite our paper:
