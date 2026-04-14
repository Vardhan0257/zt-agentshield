import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
)

response = client.chat.completions.create(
    model="qwen/qwen-2.5-72b-instruct",
    messages=[{"role": "user", "content": "Explain zero trust in one sentence."}]
)

print(response.choices[0].message.content)