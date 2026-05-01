with open("datasets/phishing.txt", "r") as f:
    lines = f.readlines()

fixed = []

for url in lines:

    url = url.strip()

    # keep removing repeated protocols
    while "https://https://" in url:
        url = url.replace(
            "https://https://",
            "https://"
        )

    while "http://http://" in url:
        url = url.replace(
            "http://http://",
            "http://"
        )

    while "https://http://" in url:
        url = url.replace(
            "https://http://",
            "http://"
        )

    fixed.append(url)

with open("datasets/phishing.txt", "w") as f:

    for url in fixed:
        f.write(url + "\n")

print("DONE CLEANING")