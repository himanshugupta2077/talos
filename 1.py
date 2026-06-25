import json

def extract(response):
    artifacts = {}

    body = getattr(response, "body", "")
    if not body:
        return artifacts

    try:
        data = json.loads(body)
    except Exception:
        return artifacts

    authentication = data.get("authentication")
    if isinstance(authentication, dict):
        token = authentication.get("token")
        if token:
            artifacts["Authorization"] = f"Bearer {token}"

    return artifacts
