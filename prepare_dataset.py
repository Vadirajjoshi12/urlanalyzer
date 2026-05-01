import pandas as pd

df = pd.read_csv("malicious_phish.csv")

print(df["type"].value_counts())

# phishing-like classes
phishing_types = [
    "phishing",
    "malware",
    "defacement"
]

# legit
legit_df = df[df["type"] == "benign"].sample(100000)

# phishing
phish_df = df[df["type"].isin(phishing_types)].sample(100000)

# save legit
with open("datasets/legit.txt", "w") as f:

    for url in legit_df["url"]:

        if not str(url).startswith("http"):
            url = "http://" + str(url)

        f.write(str(url).strip() + "\n")

# save phishing
with open("datasets/phishing.txt", "w") as f:

    for url in phish_df["url"]:

        if not str(url).startswith("http"):
            url = "http://" + str(url)

        f.write(str(url).strip() + "\n")

print("Datasets prepared successfully")
print("Legit:", len(legit_df))
print("Phishing:", len(phish_df))