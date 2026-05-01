import pandas as pd

df = pd.read_csv("verified_online.csv", header=None)

urls = ["https://" + x for x in df[1].head(50000)]

with open("datasets/legit.txt", "w") as f:
    for url in urls:
        f.write(url + "\n")

print("Legit dataset created")