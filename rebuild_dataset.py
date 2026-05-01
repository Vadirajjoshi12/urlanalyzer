with open("datasets/phishing.txt", "r") as f:
    content = f.read()

# split broken giant line into urls
urls = content.split("https://")

clean = []

for url in urls:

    url = url.strip()

    if not url:
        continue

    url = "https://" + url

    clean.append(url)

# remove duplicates
clean = list(set(clean))

with open("datasets/phishing.txt", "w") as f:

    for url in clean:
        f.write(url + "\n")

print("Dataset rebuilt:", len(clean))