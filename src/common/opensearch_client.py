import os, requests, json

class OSClient:
    def __init__(self, host=None, port=None, user=None, password=None):
        self.host = host or os.getenv('OS_HOST', 'localhost')
        self.user = user or os.getenv('OS_USER', 'admin')
        self.password = password or os.getenv('OS_PASSWORD', 'admin')
        self.auth = (self.user, self.password)
        self.verify = os.environ.get("OS_VERIFY_TLS", "true").lower() == "true"
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = self.verify
        self.session.headers.update({'Content-Type': 'application/json'})

    def ensure_inddex(slef, name: str, mappings: dict):
        url = f"{self.base}/{name}"
        r = self.session.get(url)
        if r.status_code == 404:
            self.session.put(url, json={"mappings": mappings})

    def index_doc(self, index: str, doc: dict, doc_id: str | None = None):
        if doc_id:
            url = f"{self.base}/{index}/_doc/{doc_id}"
            return self.session.put(url, json=doc)
        else:
            url = f"{self.base}/{index}/_doc"
            return self.session.post(url, json=doc)

#pregemerated by copilot -> not really used
    def create_index(self, index_name, settings=None, mappings=None):
        url = f"{self.base_url}/{index_name}"
        payload = {}
        if settings:
            payload['settings'] = settings
        if mappings:
            payload['mappings'] = mappings
        response = requests.put(url, auth=self.auth, headers=self.headers, data=json.dumps(payload))
        return response.json()

    def delete_index(self, index_name):
        url = f"{self.base_url}/{index_name}"
        response = requests.delete(url, auth=self.auth)
        return response.json()

    def index_document(self, index_name, document, doc_id=None):
        url = f"{self.base_url}/{index_name}/_doc"
        if doc_id:
            url += f"/{doc_id}"
            response = requests.put(url, auth=self.auth, headers=self.headers, data=json.dumps(document))
        else:
            response = requests.post(url, auth=self.auth, headers=self.headers, data=json.dumps(document))
        return response.json()

    def get_document(self, index_name, doc_id):
        url = f"{self.base_url}/{index_name}/_doc/{doc_id}"
        response = requests.get(url, auth=self.auth)
        return response.json()

    def search(self, index_name, query):
        url = f"{self.base_url}/{index_name}/_search"
        response = requests.get(url, auth=self.auth, headers=self.headers, data=json.dumps(query))
        return response.json()