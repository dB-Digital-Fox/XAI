# Stop the old OpenSearch bridge if running
sudo systemctl stop wazuh-xai-bridge

# Test with debug on last 10 alerts — check data: and decoder: are populated
sudo python3 alerts_xai_bridge.py --backfill 10 --dry-run --debug

# Run live, only forward level 3+
sudo python3 alerts_xai_bridge.py --min-level 3 --debug

# Install as service
sudo cp alerts_xai_bridge.py /opt/wazuh-xai-bridge/
sudo cp alerts-xai-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now alerts-xai-bridge
sudo journalctl -fu alerts-xai-bridge