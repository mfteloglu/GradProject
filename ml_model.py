import pandas as pd
import numpy as np
from sklearn import model_selection
import sklearn.ensemble as ske
import sklearn.metrics
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.feature_selection import SelectKBest, chi2


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

# Combine benign and ransomware data for DLL import features, create dataframe.
df_func_benign = pd.read_csv('dll_imports/functions_benign.csv', sep=',')
df_func_ransom = pd.read_csv('dll_imports/functions_ransom.csv', sep=',')
result = pd.concat([df_func_benign, df_func_ransom], axis=0)
df_func = result


# Combine all the features
df = pd.concat([df_pe, df_hex, df_func], axis=1)

# Add labels to hex code features
labels = df['Benign']
df_hex['Benign']  = labels
df_func['Benign'] = labels

#############################################################################################################
# To test/train different dataframes, change the df variable to the dataframe you want to test/train.
# Example for only testing the pe header features:
# df = df_pe
# Example for only testing the hex code features: 
# df = df_hex
# Example for only testing the DLL import features:
# df = df_func
#############################################################################################################

# Delete rows that include NaN values
df = df.dropna()

print(df)

print("Training the dataset using Random Forest...")

# Drops FileName and Label from data.
X = df.drop(['FileName', 'Benign'], axis=1).values

# Assigns y to label
y = df['Benign'].values

# Feature selection
X_new = SelectKBest(chi2, k=60).fit_transform(X, y)
X = X_new

results = []
for i in range(5):
    # Splitting data into training and test data
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)

    # Print the number of training and testing samples.
    print("\n\t[*] Training samples: ", len(X_train))
    print("\t[*] Testing samples: ", len(X_test))

    # Train Random forest algorithm on training dataset.
    clf = ske.RandomForestClassifier(n_estimators=50)
    clf.fit(X_train, y_train)
     
    # predictions
    rfc_predict = clf.predict(X_test)
    print("Accuracy : ")
    print(accuracy_score(y_test, rfc_predict))

    #print("=== Classification Report ===")
    #print(classification_report(y_test, rfc_predict))
    #print('\n')
    

    # Perform cross validation and print out accuracy.
    score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    #print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    results.append(round(score.mean()*100, 2))

    # Calculate f1 score.
    y_train_pred = model_selection.cross_val_predict(clf, X_train, y_train, cv=10)
    f = f1_score(y_train, y_train_pred)
    #print("\t[*] F1 Score: ", round(f*100, 2), '%')

#print("Average CV result:", np.mean(results))
