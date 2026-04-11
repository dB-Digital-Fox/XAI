# 1. Install dependency
pip3 install requests urllib3

# 2. Copy bridge to a permanent location
sudo mkdir -p /opt/wazuh-xai-bridge
sudo cp os_xai_bridge.py /opt/wazuh-xai-bridge/

# 3. Edit OpenSearch credentials at the top of the script
sudo nano /opt/wazuh-xai-bridge/os_xai_bridge.py
# Change: OPENSEARCH_PASS = "your-actual-password"

# 4. Test it manually first
python3 /opt/wazuh-xai-bridge/os_xai_bridge.py --dry-run --once
python3 /opt/wazuh-xai-bridge/os_xai_bridge.py --since 30m --dry-run

# 5. Remove the old integration from ossec.conf
# Delete the <integration> block, then:
sudo systemctl restart wazuh-manager

# 6. Install and start the service
sudo cp wazuh-xai-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-xai-bridge
sudo journalctl -fu wazuh-xai-bridge