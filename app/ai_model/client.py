import httpx, os

MODEL_API_URL = os.getenv("MODEL_API_URL", "http://host.docker.internal:8080/chat")

async def get_model_response(prompt: str):
    payload = {
        "prompt": prompt,
        "max_tokens": 512,
        "temperature": 0.7,
        "top_p": 0.9,
        "do_sample": True
    }
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.post(MODEL_API_URL, json=payload)
        r.raise_for_status()
        return r.json().get("output", r.json())
