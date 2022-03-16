import pandas as pd
import numpy as np
import py
from sklearn import model_selection
import sklearn.ensemble as ske
import sklearn.metrics
from sklearn.metrics import f1_score, classification_report


# Combine benign and ransomware data for PE header features, create dataframe.
df_pe_benign = pd.read_csv('pe_header_features/data_benign.csv', sep=',')
df_pe_ransomware = pd.read_csv('pe_header_features/data_ransomware.csv', sep=',')
result = pd.concat([df_pe_benign, df_pe_ransomware], axis=0)
df_pe = result


# Combine benign and ransomware data for hex code features, create dataframe.
df_hex_benign = pd.read_csv('disassembler_opcodes/hexcodes_benign_percentages.csv', sep=',')
df_hex_ransomware = pd.read_csv('disassembler_opcodes/hexcodes_ransomware_percentages.csv', sep=',')
result = pd.concat([df_hex_benign, df_hex_ransomware], axis=0)
df_hex = result

# Combine pe header and hex code features
df = pd.concat([df_pe, df_hex], axis=1)

# Add labels to hex code features
labels = df['Benign']
df_hex['Benign']  = labels

# Delete rows that include NaN values
df = df.dropna()

print(df)

print("Training the dataset using Random Forest...")

# Drops FileName and Label from data.
X = df.drop(['FileName', 'Benign'], axis=1).values


# Assigns y to label
y = df['Benign'].values

# Splitting data into training and test data
X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)

# Print the number of training and testing samples.
print("\n\t[*] Training samples: ", len(X_train))
print("\t[*] Testing samples: ", len(X_test))

# Train Random forest algorithm on training dataset.
clf = ske.RandomForestClassifier(n_estimators=50)
clf.fit(X_train, y_train)
''' 
# predictions
rfc_predict = clf.predict(X_test)
print("=== Classification Report ===")
print(classification_report(y_test, rfc_predict))
print('\n')
'''

# Perform cross validation and print out accuracy.
score = model_selection.cross_val_score(clf, X_test, y_test, cv=3)
print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

# Calculate f1 score.
y_train_pred = model_selection.cross_val_predict(clf, X_train, y_train, cv=3)
f = f1_score(y_train, y_train_pred)
print("\t[*] F1 Score: ", round(f*100, 2), '%')
