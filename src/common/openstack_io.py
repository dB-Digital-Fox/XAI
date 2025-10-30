import os, json
try:
    import openstack
except Exception:
    openstack = None

def _conn():
    if openstack is None:
        raise RuntimeError("openstacksdk not installed")
    return openstack.connect(
        auth_url=os.environ["OS_AUTH_URL"],
        username=os.environ["OS_USERNAME"],
        password=os.environ["OS_PASSWORD"],
        project_name=os.environ["OS_PROJECT_NAME"],
        user_domain_name=os.getenv("OS_USER_DOMAIN_NAME","Default"),
        project_domain_name=os.getenv("OS_PROJECT_DOMAIN_NAME","Default"),
    )

def fetch_json_objects(container: str, prefix: str):
    c = _conn()
    logs = []
    for obj in c.object_store.objects(container, prefix=prefix):
        data = c.object_store.get_object(container, obj.name)
        body = data.data if hasattr(data, "data") else data
        text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else str(body)
        # Try JSON array/object
        try:
            j = json.loads(text)
            if isinstance(j, list):
                logs.extend(j)
            elif isinstance(j, dict):
                logs.append(j)
            continue
        except json.JSONDecodeError:
            pass
        # JSONL fallback
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return logs
