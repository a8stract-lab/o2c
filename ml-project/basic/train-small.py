from sklearn.tree import DecisionTreeClassifier
from time import time
import pandas
import numpy as np
from sklearn.metrics import accuracy_score,precision_score,recall_score


train_df = pandas.read_csv("train_split_small.csv",index_col=0)
y = train_df["label"]
index_list = []
for i in range(1024):
    index_list.append(str(i))
x = train_df[index_list]
train_x = x.iloc[:4000] # 前4000个samples作为训练集
train_y = y.iloc[:4000]
test_x = x.iloc[4000:]
test_y = y.iloc[4000:]

# decision tree
time_bf = time()
dt = DecisionTreeClassifier()
dt.fit(train_x,train_y)
time_af = time()
print("decision tree time:", time_af-time_bf)
pred_y = dt.predict(test_x)
print("decision tree test_acc:",accuracy_score(test_y,pred_y))
print('decision tree Macro precision', precision_score(test_y, pred_y, average='macro'))
print('decision tree Macro recall', recall_score(test_y, pred_y, average='macro'))

print(dt.tree_.max_depth)

# current_logdir = "res/"
# with open('%s/childrenLeft' % current_logdir, 'wb') as f:
#     dt.tree_.children_left.tofile(f)
# with open('%s/childrenRight' % current_logdir, 'wb') as f:
#     dt.tree_.children_right.tofile(f)
# with open('%s/value' % current_logdir, 'wb') as f:
#     dt.tree_.value.squeeze().argmax(axis=1).tofile(f)
# with open('%s/feature' % current_logdir, 'wb') as f:
#     dt.tree_.feature.tofile(f)
# with open('%s/threshold' % current_logdir, 'wb') as f:
#     dt.tree_.threshold.round().astype(np.int64).tofile(f)

