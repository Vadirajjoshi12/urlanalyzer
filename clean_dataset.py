clean_urls = set()

with open("datasets/phishing.txt", "r") as f:
    for line in f:

        url = line.strip()

        # remove duplicate https://https://
        url = url.replace("https://https://", "https://")
        url = url.replace("http://http://", "http://")

        # keep only valid URLs
        if url.startswith("http://") or url.startswith("https://"):

            clean_urls.add(url)

with open("datasets/final_phishing.txt", "w") as f:
    for url in clean_urls:
        f.write(url + "\\n")

print("Clean URLs:", len(clean_urls))