# OpenFHE - SVM
OpenFHE-Python-based Examples of Encrypted Support Vector Machine Inference based on [this C++ example](https://github.com/caesaretos/svm-fhe/tree/main).

## Preparing the environment

Before running any code from this repo, make sure you have a working [Python 3.6+](https://www.python.org/) installation. Then, install the dependencies:

**1 - PyBind11:**

```bash
pip install "pybind11[global]" # or alternatively, if you use conda:
conda install -c conda-forge pybind11
```

**2 - OpenFHE-development:**

```bash
git clone git@github.com:openfheorg/openfhe-development.git
cd openfhe-development
mkdir build
cd build
cmake ..
make -j N  # number of processors - 4 in my case
sudo make install && cd ../.. # to get back to original path
```

**3 - OpenFHE-Python:**

```bash
git clone git@github.com:openfheorg/openfhe-python.git
cd openfhe-python
mkdir build
cd build
cmake .. # or alternatively for conda: cmake .. -DPYTHON_EXECUTABLE_PATH=$CONDA_PREFIX/bin/python
make -j N  # number of processors - 4 in my case
sudo make install && cd ../.. # to get back to original path
```

**4 - Model Requirements:**

```bash
git clone git@github.com:reneroliveira/openfhe-svm.git
cd openfhe-svm
pip install -r requirements.txt
```
## Running

First, install `openfhe-python` following the instructions of [library's repository](https://github.com/openfheorg/openfhe-python/).

Then, you can run `python model_training.py` to train and save the model weights, and then call the encrypted model files for inference. All necessary data is inside `data/` directory, but if you want to reproduce the data generation run the `get_data.py` file.

The main files are `encrypted_svm_linear.py` and `encrypted_svm_poly.py`, which are the encrypted versions of inference of the linear and polynomial kernel SVM models, respectively.

