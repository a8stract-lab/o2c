from sklearn.tree import DecisionTreeClassifier
import numpy as np

# Sample data
X = np.array([[1, 2], [4, 5], [7, 8]])
y = np.array([0, 1, 0])

# Train the model
clf = DecisionTreeClassifier()
clf.fit(X, y)

# Extract attributes
children_left = clf.tree_.children_left
children_right = clf.tree_.children_right
feature = clf.tree_.feature
threshold = np.floor(clf.tree_.threshold).astype(np.int64)
value = clf.tree_.value.squeeze().argmax(axis=1)

print("childrenLeft:", children_left)
print("childrenRight:", children_right)
print("feature:", feature)
print("threshold:", threshold)
print("value:", value)
print("depth:", clf.tree_.max_depth)

print(clf.predict([[4,2]]))


current_logdir = "res/"
with open('%s/childrenLeft' % current_logdir, 'wb') as f:
    clf.tree_.children_left.tofile(f)
with open('%s/childrenRight' % current_logdir, 'wb') as f:
    clf.tree_.children_right.tofile(f)
with open('%s/value' % current_logdir, 'wb') as f:
    clf.tree_.value.squeeze().argmax(axis=1).tofile(f)
with open('%s/feature' % current_logdir, 'wb') as f:
    clf.tree_.feature.tofile(f)
with open('%s/threshold' % current_logdir, 'wb') as f:
    # clf.tree_.threshold.round().astype(np.int64).tofile(f)
    np.floor(clf.tree_.threshold).astype(np.int64).tofile(f)