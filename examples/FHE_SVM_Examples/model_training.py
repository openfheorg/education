import pandas as pd
import numpy as np
from sklearn.svm import SVC

# Load the data
X_train = pd.read_csv('data/credit_approval_train.csv')
X_test = pd.read_csv('data/credit_approval_test.csv')
y_train = pd.read_csv('data/credit_approval_target_train.csv')
y_test = pd.read_csv('data/credit_approval_target_test.csv')

# Model Training
print("---- Starting Models Training ----")

print("Starting SVM Linear")
svc_linear = SVC(kernel='linear')
svc_linear.fit(X_train, y_train.values.ravel())
print("SVM Linear Completed")

svc_poly = SVC(kernel='poly',degree=3,gamma=2)
svc_poly.fit(X_train, y_train.values.ravel())
print("SVM Poly Completed")

print("---- Model Training Completed! ----")

decision_function = svc_linear.decision_function(X_test)
ytestscore = decision_function[0]

decision_function_poly = svc_poly.decision_function(X_test)
ytestscore_poly = decision_function_poly[0]

# Saving Results
np.savetxt("models/weights.txt", svc_linear.coef_)
np.savetxt("models/intercept.txt", svc_linear.intercept_)
np.savetxt("data/ytestscore.txt", [ytestscore])
np.savetxt("models/dual_coef.txt", svc_poly.dual_coef_)
np.savetxt("models/support_vectors.txt", svc_poly.support_vectors_)
np.savetxt("models/intercept_poly.txt", svc_poly.intercept_)
np.savetxt("data/ytestscore_poly.txt", [ytestscore_poly])


