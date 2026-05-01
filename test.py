import google.generativeai as genai

API_KEY = "AIzaSyDxZKpUhKmQROjEyeBkTMjDBwZklZd3gaE"

print("API KEY FOUND:", bool(API_KEY))

try:

    genai.configure(api_key=API_KEY)

    model = genai.GenerativeModel("gemini-2.5-flash")

    response = model.generate_content(
        "Say hello in one sentence."
    )

    print("\nSUCCESS\n")
    print(response.text)

except Exception as e:

    print("\nERROR:\n")
    print(e)