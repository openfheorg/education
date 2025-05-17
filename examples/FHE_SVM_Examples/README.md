# 🔒 FHE-SVM-Examples

This repository contains a collection of scripts and notebooks demonstrating the use of **Fully Homomorphic Encryption (FHE)** in **Support Vector Machine (SVM)** models. The examples explore privacy-preserving machine learning by performing encrypted inference without ever decrypting sensitive data.

---

## 📁 Project Structure

```

FHE-SVM-Examples/
├── data/                          # Raw and/or preprocessed datasets
├── models/                        # Serialized/trained models
├── results/                       # Outputs and evaluation results
├── Advanced-FHE-SVM-Experiments Steps.ipynb   # Walkthrough of advanced FHE-SVM usage
├── encrypted\_svm\_linear.py        # Linear kernel SVM with FHE
├── encrypted\_svm\_linear5.py
├── encrypted\_svm\_lineartest.py
├── encrypted\_svm\_poly.py          # Polynomial kernel SVM with FHE
├── encrypted\_svm\_poly5.py
├── encrypted\_svm\_polytest.py
├── FHE-SMV Documentation.ipynb    # Detailed documentation and experimental notes
├── get\_data.py                    # Utility to load/generate dataset
├── model\_training.py              # SVM model training pipeline
├── requirements.txt               # Python dependencies
├── SVM Paper\_results\_linear.csv and poly.csv   # Evaluation results
└── README.md                      # This file

````

---

## 🎯 Objective

The main goal of this project is to implement and evaluate **privacy-preserving SVM classification** using **homomorphic encryption**, allowing encrypted data to be classified without decryption — enabling secure inference in sensitive domains such as:

- Healthcare
- Financial analytics
- Edge/IoT environments

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/billbuchanan/homomorphic_ml/FHE-SVM-Examples.git
cd FHE-SVM-Examples
````

### 2. Install Required Packages

```bash
pip install -r requirements.txt
```

Ensure you have Python 3.8+ and dependencies such as `numpy`, `scikit-learn`, `pandas`, and any FHE-specific libraries (like OpenFHE bindings, if used).

---

## 🚀 Running Examples

You can run different encrypted SVM variants from the command line or notebooks:

### Linear Kernel SVM (Encrypted)

```bash
python encrypted_svm_linear.py
```

### Polynomial Kernel SVM (Encrypted)

```bash
python encrypted_svm_poly.py
```

### Test and Experiment Variants

* `encrypted_svm_linear5.py` and `encrypted_svm_poly5.py` include batch experiments.
* `*_test.py` files contain testing utilities.

### Notebooks

Open in Jupyter:

```bash
jupyter notebook "Advanced-FHE-SVM-Experiments Steps.ipynb"
```

---

## 📊 Results

Sample evaluation metrics and output are saved in:

* `SVM Paper_results_linear.csv`
* `SVM Paper_results_poly.csv`

Example:

| Kernel     | Accuracy | Encryption Time | Inference Time |
| ---------- | -------- | --------------- | -------------- |
| Linear     | 91.2%    | 1.1s            | 2.5s           |
| Polynomial | 89.4%    | 1.3s            | 3.2s           |

---

## 🔐 Why FHE?

**Fully Homomorphic Encryption (FHE)** enables computations directly on encrypted data, preserving privacy and confidentiality. It's particularly useful when:

* Data must remain encrypted (GDPR, HIPAA).
* You want to perform ML on untrusted platforms (e.g., cloud).

This project demonstrates how SVMs — a foundational ML technique — can be adapted to run under these constraints.

---

## 🧠 Additional Notes

* To train models, use `model_training.py`
* To load and prepare datasets, see `get_data.py`
* More detailed step-by-step guidance is in `Advanced-FHE-SVM-Experiments Steps.ipynb` and `FHE-SMV Documentation.ipynb`

