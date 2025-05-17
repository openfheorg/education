# 🩺 Encrypted SVM for Diabetes Prediction

This project implements **privacy-preserving SVM classification** for diabetes prediction using **CKKS homomorphic encryption**. It demonstrates how encrypted inference can be achieved using both linear and polynomial SVM kernels while keeping patient data confidential.

---

## 📁 Directory Structure

```

Diabetes/
├── Diabetes-LinearCKKS.py       # Linear kernel SVM with CKKS encryption
├── Diabetes-PolyCKKS.py         # Polynomial kernel SVM with CKKS encryption
├── PIDD.csv                     # PIMA Indian Diabetes Dataset
├── get\_data.py                  # Utility to preprocess/load the dataset
├── model\_training.py            # Train plain-text SVM models
└── README.md                    # Project documentation (this file)

````

---

## 📊 Dataset

We use the **PIMA Indian Diabetes Dataset (PIDD)** which contains medical and demographic data for binary diabetes classification.

**Features include:**
- Number of pregnancies
- Glucose concentration
- Blood pressure
- Skin thickness
- Insulin level
- BMI
- Diabetes pedigree function
- Age

**Target:**
- `1`: Positive for diabetes
- `0`: Negative for diabetes

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/billbuchanan/homomorphic_ml/Diabetes.git
cd Diabetes
````

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

*Note:* You may need to install FHE libraries (like [OpenFHE](https://github.com/openfheorg/openfhe-development) or SEAL) separately, depending on the backend used in your scripts.

---

## 🚀 Running the Code

### Run Linear CKKS Encrypted Inference

```bash
python Diabetes-LinearCKKS.py
```

### Run Polynomial CKKS Encrypted Inference

```bash
python Diabetes-PolyCKKS.py
```

---

## 🧪 How It Works

1. **Data Loading**: `get_data.py` handles reading and normalizing the `PIDD.csv` file.
2. **Training**: Use `model_training.py` to train a plain SVM model for comparison and to extract support vectors.
3. **Encryption & Inference**: The main scripts (`Diabetes-LinearCKKS.py` and `Diabetes-PolyCKKS.py`) use the trained model for inference on encrypted inputs using the CKKS scheme.

---

## ✅ Sample Output (Encrypted Inference)

| Kernel     | Accuracy | Inference (Encrypted) Time | Encryption Scheme |
| ---------- | -------- | -------------------------- | ----------------- |
| Linear     | 85.6%    | \~1.4s                     | CKKS              |
| Polynomial | 84.1%    | \~2.0s                     | CKKS              |

---

## 🔐 Why Use CKKS?

**CKKS** (Cheon-Kim-Kim-Song) is a homomorphic encryption scheme supporting **approximate arithmetic**, ideal for ML workloads like SVMs. It enables inference on encrypted floats — allowing privacy-preserving predictions without decrypting sensitive health data.

---

## 📌 References

* PIMA Indian Diabetes Dataset (PIDD): [UCI Repository](https://www.kaggle.com/datasets/uciml/pima-indians-diabetes-database)
* Homomorphic Encryption: CKKS scheme
* Scikit-learn (for plaintext training)


