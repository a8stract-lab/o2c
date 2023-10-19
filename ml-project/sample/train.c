#include <stdio.h>
#include <stdlib.h>

// Define the maximum number of nodes for simplicity
#define MAX_NODES 10

// Arrays to hold the tree attributes
long childrenLeft[MAX_NODES];
long childrenRight[MAX_NODES];
long feature[MAX_NODES];
long threshold[MAX_NODES];
long value[MAX_NODES];

void print(char *name, long *arr)
{
    printf("%s: [ ", name);
    for (int i = 0;i < MAX_NODES;i++) {
        printf("%ld ", arr[i]);
    }
    printf("]\n");
}

// Function to read tree attributes from files
void readTreeAttributes() {
    FILE *fp;

    fp = fopen("res/childrenLeft", "rb");
    fread(childrenLeft, sizeof(long), MAX_NODES, fp);
    fclose(fp);
    print("childrenLeft", childrenLeft);

    fp = fopen("res/childrenRight", "rb");
    fread(childrenRight, sizeof(long), MAX_NODES, fp);
    fclose(fp);
    print("childrenRight", childrenRight);

    fp = fopen("res/feature", "rb");
    fread(feature, sizeof(long), MAX_NODES, fp);
    fclose(fp);
    print("feature", feature);

    fp = fopen("res/threshold", "rb");
    fread(threshold, sizeof(long), MAX_NODES, fp);
    fclose(fp);
    print("threshold", threshold);

    fp = fopen("res/value", "rb");
    fread(value, sizeof(long), MAX_NODES, fp);
    fclose(fp);
    print("value", value);
}

int find_depth(int node, long *childrenLeft, long *childrenRight) {
    // Base case: if the node is a leaf node, return 0
    if (childrenLeft[node] == -1 && childrenRight[node] == -1) {
        return 0;
    }

    // Initialize depth to 0
    int depth = 0;

    // Traverse the left subtree if it exists
    if (childrenLeft[node] != -1) {
        int left_depth = 1 + find_depth(childrenLeft[node], childrenLeft, childrenRight);
        depth = (left_depth > depth) ? left_depth : depth;
    }

    // Traverse the right subtree if it exists
    if (childrenRight[node] != -1) {
        int right_depth = 1 + find_depth(childrenRight[node], childrenLeft, childrenRight);
        depth = (right_depth > depth) ? right_depth : depth;
    }

    return depth;
}

// Function to traverse the decision tree
void predict(long *sample) {
    int node = 0;
    while (feature[node] != -2) {
        printf("node:%d, sample[%ld]:%ld, threshold: %ld\n", node, feature[node], sample[feature[node]], threshold[node]);
        if (sample[feature[node]] <= threshold[node]) {
            node = childrenLeft[node];
        } else {
            node = childrenRight[node];
        }
    }
    printf("Predicted value: [%ld]\n", value[node]);
}

int main() {
    // Read tree attributes from files
    readTreeAttributes();

    // Sample data point
    long sample[] = {4, 2};

    // Make prediction
    predict(sample);
    printf("depth: %d\n", find_depth(0, childrenLeft, childrenRight));

    return 0;
}