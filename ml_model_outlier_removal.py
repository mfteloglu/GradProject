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
#df = pd.concat([df_hex, df_func, df_pe], axis=1)

# Add labels to hex code features
#df_func['Benign'] = labels
df = pd.merge(df_hex, df_func, how="inner", on="FileName")
df = pd.merge(df, df_pe, how="inner", on="FileName")
labels = df['Benign']


#############################################################################################################
# To test/train different dataframes, change the df variable to the dataframe you want to test/train.
# Example for only testing the pe header features:
# df = df_pe
# Example for only testing the hex code features: 
#df = df_hex
# Example for only testing the DLL import features:
# df = df_func
#############################################################################################################

# Delete rows that include NaN values
df = df.dropna()
df.to_csv("with_outliers.csv")
print("Original df shape:", df.shape)

coefficient = 7.0
df_hex_trimmed = df_hex.dropna()
for column in df_hex_trimmed:
    if column != "FileName" and column != "Benign":
        highest = df_hex_trimmed[column].mean() + coefficient*df_hex_trimmed[column].std()
        lowest = df_hex_trimmed[column].mean() - coefficient*df_hex_trimmed[column].std()     
        df_hex_trimmed = df_hex_trimmed.drop(df_hex_trimmed[(df_hex_trimmed[column] > highest) | (df_hex_trimmed[column] < lowest)].index)

print("Trimmed df_hex shape:", df_hex_trimmed.shape)


df_trimmed = pd.merge(df_hex_trimmed, df_func, how="inner", on="FileName")
df_trimmed = pd.merge(df_trimmed, df_pe, how="inner", on="FileName")
df_trimmed = df_trimmed.dropna()
#df_trimmed = df_trimmed.drop(df_trimmed.columns[257:528], axis=1)
df_trimmed.to_csv("without_outliers.csv")
print("Trimmed df shape:", df_trimmed.shape)
print("Training the dataset using Random Forest...")

# Drops FileName and Label from data.
#X = df.drop(['FileName', 'Benign'], axis=1).values
X = df_trimmed.drop(['FileName', 'Benign'], axis=1).values

# Assigns y to label
#y = df['Benign'].values
y = df_trimmed['Benign'].values
# Feature selection
X_new = SelectKBest(chi2, k=100).fit_transform(X, y)
X = X_new



results = []
for i in range(10):
    # Splitting data into training and test data
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)

    # Print the number of training and testing samples.
    #print("\n\t[*] Training samples: ", len(X_train))
    #print("\t[*] Testing samples: ", len(X_test))

    # Train Random forest algorithm on training dataset.
    clf = ske.RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    
    # predictions
    rfc_predict = clf.predict(X_test)
    #print("Accuracy : ")
    #print(accuracy_score(y_test, rfc_predict))

    #print("=== Classification Report ===")
    #print(classification_report(y_test, rfc_predict))
    #print('\n')
    

    # Perform cross validation and print out accuracy.
    #score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    #print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    results.append(accuracy_score(y_test, rfc_predict))

    # Calculate f1 score.
    #y_train_pred = model_selection.cross_val_predict(clf, X_train, y_train, cv=10)
    #f = f1_score(y_train, y_train_pred)
    #print("\t[*] F1 Score: ", round(f*100, 2), '%')

print("Average accuracy result:", np.mean(results))



