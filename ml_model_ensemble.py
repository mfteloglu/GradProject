import pandas as pd
import numpy as np
from sklearn import model_selection
import sklearn.ensemble as ske
import sklearn.metrics
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.utils import shuffle


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
# df = df_hex
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

df_pe_trimmed = df_pe[df_pe["FileName"].isin(df_hex_trimmed["FileName"])]
df_func_trimmed = df_func[df_func["FileName"].isin(df_hex_trimmed["FileName"])]
labels = df_pe_trimmed['Benign']
df_hex_trimmed["Benign"] = labels
df_func_trimmed["Benign"] = labels


df_trimmed = pd.merge(df_hex_trimmed, df_func_trimmed, how="inner", on="FileName")
df_trimmed = pd.merge(df_trimmed, df_pe_trimmed, how="inner", on="FileName")
df_trimmed = df_trimmed.dropna()
#df_trimmed = df_trimmed.drop(df_trimmed.columns[257:528], axis=1)
df_trimmed.to_csv("without_outliers.csv")
print("Trimmed df shape:", df_trimmed.shape)
print("Training the dataset using Random Forest...")

# Drops FileName and Label from data.
#X = df.drop(['FileName', 'Benign'], axis=1).values
X1 = df_hex_trimmed.drop(['FileName', 'Benign'], axis=1).values
# Assigns y to label
#y = df['Benign'].values
y1 = df_hex_trimmed['Benign'].values
# Feature selection
X_new1 = SelectKBest(chi2, k=100).fit_transform(X1, y1)
X1 = X_new1


X2 = df_pe_trimmed.drop(['FileName', 'Benign'], axis=1).values

y2 = df_pe_trimmed['Benign'].values

X_new2 = SelectKBest(chi2, k=15).fit_transform(X2, y2)
X2 = X_new2


X3 = df_func_trimmed.drop(['FileName', 'Benign'], axis=1).values

y3 = df_func_trimmed['Benign'].values

X_new3 = SelectKBest(chi2, k=100).fit_transform(X3, y3)
X3 = X_new3


results = []
for i in range(10):
    # Splitting data into training and test data

    X_train1, X_test1 = X1[150:1483, :], X1[0:150, :]
    X_test1 = np.insert(X_test1, X_test1.shape[0], X1[1483:, :], axis=0)
    y_train1, y_test1 = y1[150:1483], y1[0:150]
    y_test1 = np.insert(y_test1, y_test1.shape[0], y1[1483:], axis=0)

    X_train2, X_test2 = X2[150:1483, :], X2[0:150, :]
    X_test2 = np.insert(X_test2, X_test2.shape[0], X2[1483:, :], axis=0)
    y_train2, y_test2 = y2[150:1483], y2[0:150]
    y_test2 = np.insert(y_test2, y_test2.shape[0], y2[1483:], axis=0)

    X_train3, X_test3 = X3[150:1483, :], X3[0:150, :]
    X_test3 = np.insert(X_test3, X_test3.shape[0], X3[1483:, :], axis=0)
    y_train3, y_test3 = y3[150:1483], y3[0:150]
    y_test3 = np.insert(y_test3, y_test3.shape[0], y3[1483:], axis=0)
     

    # Print the number of training and testing samples.
    #print("\n\t[*] Training samples: ", len(X_train))
    #print("\t[*] Testing samples: ", len(X_test))

    # Train Random forest algorithm on training dataset.
    clf1 = ske.RandomForestClassifier(n_estimators=100)
    clf1.fit(X_train1, y_train1)
    
    # predictions

    rfc_predict1 = clf1.predict(X_test1)
    #print("Accuracy : ")
    #print(accuracy_score(y_test, rfc_predict))

    clf2 = ske.RandomForestClassifier(n_estimators=100)
    clf2.fit(X_train2, y_train2)
    
    # predictions
    rfc_predict2 = clf2.predict(X_test2)



    clf3 = ske.RandomForestClassifier(n_estimators=100)
    clf3.fit(X_train3, y_train3)
    
    # predictions
    rfc_predict3 = clf3.predict(X_test3)

    #print("=== Classification Report ===")
    #print(classification_report(y_test, rfc_predict))
    #print('\n')
    
    rfc_predict_final = rfc_predict1

    for i in range(len(rfc_predict1)):
        if rfc_predict1[i] + rfc_predict2[i] + rfc_predict3[i] > 1:
            rfc_predict_final[i] = 1
        else:
            rfc_predict_final[i] = 0


    # Perform cross validation and print out accuracy.
    #score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    #print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    results.append(accuracy_score(y_test3, rfc_predict_final))

    # Calculate f1 score.
    #y_train_pred = model_selection.cross_val_predict(clf, X_train, y_train, cv=10)
    #f = f1_score(y_train, y_train_pred)
    #print("\t[*] F1 Score: ", round(f*100, 2), '%')

print("Average accuracy result:", np.mean(results))



