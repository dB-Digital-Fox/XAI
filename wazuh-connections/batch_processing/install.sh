sudo cp batch_processor.py /opt/wazuh-xai-bridge/
sudo cp batch-processor.timer /etc/systemd/system/
sudo systemctl daemon-reload

# Test first
sudo python3 batch_processor.py --window 60 --dry-run
sudo python3 batch_processor.py --window 60 --dump-only  # see what gets collected

# Run live
sudo python3 batch_processor.py --window 60

# Install timer (every 10 min)
sudo systemctl enable --now batch-processor.timer

# If XAI was down and batches failed
sudo python3 batch_processor.py --retry-failed