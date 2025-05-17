# Credit card fraud using OpenFHE with Python wrapper

## Downloading and parsing data set
To download the data and split the data sets:

```
python get_data.py
```

This pulls down the required dataset with:

```
credit_approval = fetch_ucirepo(id='Credit Approval')
```

This downloads the credit card approval dataset [here](https://archive.ics.uci.edu/dataset/27/credit+approval), and creates the following files:

```
credit_approval.csv
credit_approval_target_test.csv
credit_approval_target_train.csv
credit_approval_test.csv
credit_approval_train.csv
```

The credit_approval.csv file contains six features for the credit card dataset, and where credit_approval_train.csv contains the training data, and credit_approval_test.csv contains the data to test the model. The credit_approval_target_test.csv and credit_approval_target_train.csv files have the target training factor (fraudulant or not). The split between the training data and the test data is 80%/20%.

There are 16 features in the dataset (of which are anonymised so that it does not leak any sensitive information), of which A2, A3, A8, A11, A14 and A15 are numeric values, and which will be used in the learning:

```
A1:	b, a.
A2:	continuous.
A3:	continuous.
A4:	u, y, l, t.
A5:	g, p, gg.
A6:	c, d, cc, i, j, k, m, r, q, w, x, e, aa, ff.
A7:	v, h, bb, j, n, z, dd, ff, o.
A8:	continuous.
A9:	t, f.
A10:	t, f.
A11:	continuous.
A12:	t, f.
A13:	g, p, s.
A14:	continuous.
A15:	continuous.
A16: +,-         (class attribute)
```
In the training, we will use the first four features (A2, A3, A8 and A11). 

## Training the model
Next we can train the model with:

```
python model_training.py
```

and which builds a model in the models folder:

```
dual_coef.txt
intercept.txt
intercept_poly.txt
support_vectors.txt
weights.txt
```

## Running the model with encrypted data
Finally, we can run the model with encrypted data:

```
python encrypted_svm_linear.py
```

A run of this gives:

```
---- Loading Data and Model ----
---- Data Loaded! ----
---- Model Loaded! ----
CKKS is using ring dimension 16384
Input pt_weights: (1.89376, -0.0995155, 1.3739, 0.565907,  ... ); Estimated precision: 50 bits

Input pt_bias: (0.161167,  ... ); Estimated precision: 50 bits

Linear-SVM inference took 0.051833391189575195 ms
Expected score = -0.8002993455043914
Predicted score (1st element) = (-0.800299, 7.43123e-15, -2.47025e-14, -6.37651e-15,  ... ); Estimated precision: 44 bits
```
We can see that the CKKS modulus used is 16,384. The expected score is  -0.8002993455043914, and the predicted score is -0.800299.


