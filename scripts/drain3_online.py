from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
import json, sys

config = TemplateMinerConfig()
config.load_default_config()
miner = TemplateMiner(config=config)

for line in sys.stdin:
    msg = json.loads(line).get("message", "")
    r = miner.add_log_message(msg)
    template_id = r["cluster_id"]
    # store back into your event as enrich.template_id or cache a map
    print(json.dumps({"template_id": template_id, "template": r["template_mined"]}))