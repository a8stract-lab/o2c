from sklearn.tree import DecisionTreeClassifier
from time import time
import pandas
import numpy as np
from sklearn.metrics import accuracy_score,precision_score,recall_score
from sklearn.tree import _tree


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

def find_nodes_for_feature(decision_tree, feature_index):
    tree = decision_tree.tree_
    nodes_with_feature = []

    for node in range(tree.node_count):
        if tree.feature[node] == feature_index:
            nodes_with_feature.append(node)

    return nodes_with_feature

def feature_node_info(decision_tree, feature_index):
    tree = decision_tree.tree_
    nodes_info = []

    for node in range(tree.node_count):
        if tree.feature[node] == feature_index:
            node_info = {
                "node_id": node,
                "threshold": tree.threshold[node],
                "left_child": tree.children_left[node],
                "right_child": tree.children_right[node],
                "impurity": tree.impurity[node],
                "n_node_samples": tree.n_node_samples[node]
            }
            nodes_info.append(node_info)

    return nodes_info


def tree_analysis(decision_tree):
    tree = decision_tree.tree_
    # Tree Depth
    print("Depth of the Decision Tree:", tree.max_depth)

    # Number of Nodes
    num_nodes = tree.node_count
    print("Number of Nodes:", num_nodes)

    # Node Weights
    print("Node Weights:")
    for i in range(num_nodes):
        if tree.children_left[i] != _tree.TREE_LEAF:
            print(f"Node {i} Weight: {tree.weighted_n_node_samples[i]}")

    print("Node importance:")
    importances = dt.feature_importances_
    for idx, importance in enumerate(importances):
        print(f"Feature {index_list[idx]} Importance: {importance}")

    print('most important feature')
    nodes = find_nodes_for_feature(dt, 0)
    print("Nodes using the feature:", nodes, len(nodes))

    nodes_info = feature_node_info(dt, 0)
    for info in nodes_info:
        print("Node ID:", info["node_id"])
        print("Threshold for split:", info["threshold"])
        print("Left child:", info["left_child"])
        print("Right child:", info["right_child"])
        print("Impurity:", info["impurity"])
        print("Number of samples:", info["n_node_samples"])
        print("------")

tree_analysis(dt)


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

