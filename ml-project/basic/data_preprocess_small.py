import pandas as pd
import pickle
import os
import math
from tqdm import tqdm
from decimal import Decimal





def transform_int(x):
    return int(x,16)

total_number = 16384
split_number = 16
total_feature = int(total_number/split_number)

df = pd.read_csv("train-data/kmalloc-8.csv",header=None,names=["label","byte","feature"])
df.drop_duplicates(inplace=True)
for i in range(total_feature):
    if df["feature"].iloc[0][i * 16:(i + 1) * 16] == "":
        df[i] = 0
    else:
        df[i] = df["feature"].str.slice(i * 16, (i + 1) * 16)
        df[i] = df[i].replace("", "0")
        df[i] = df[i].apply(transform_int)
    if i % 5 == 0:
        df = df.copy()
df.drop(labels=["feature","byte"],axis=1,inplace=True)


df["label"] = df["label"].astype("category")
df["label"] = df["label"].cat.codes
df.to_csv("train_split_small.csv")

# train_df.to_csv("trans_data_train_split.csv")
# test_df.to_csv("trans_data_test_split.csv")
#df.to_csv("all_split.csv")



