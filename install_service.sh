#!/bin/bash

# EchoStream Service Installation Script
# This script installs the EchoStream service with the correct user and paths

echo "=========================================="
echo "EchoStream Service Installation"
echo "=========================================="

# Get current user
CURRENT_USER=$(whoami)
CURRENT_HOME=$(eval echo ~$CURRENT_USER)
PROJECT_DIR=$(pwd)

echo "Current user: $CURRENT_USER"
echo "Home directory: $CURRENT_HOME"
echo "Project directory: $PROJECT_DIR"

# Create a temporary service file with the correct paths
TEMP_SERVICE="/tmp/echostream.service.tmp"

cat > "$TEMP_SERVICE" << EOF
[Unit]
Description=EchoStream Audio Communication Service
After=network.target mosquitto.service sound.target
Wants=mosquitto.service

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/run_with_config.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# GPIO permissions
SupplementaryGroups=gpio

# Audio permissions
SupplementaryGroups=audio

# Environment variables
Environment=DISPLAY=:0

[Install]
WantedBy=multi-user.target
EOF

echo "Service file created with correct paths:"
echo "  User: $CURRENT_USER"
echo "  Working Directory: $PROJECT_DIR"
echo "  ExecStart: $PROJECT_DIR/run_with_config.sh"
echo ""

# Make sure the run script is executable
chmod +x "$PROJECT_DIR/run_with_config.sh"

# Install the service
echo "Installing EchoStream service..."
sudo cp "$TEMP_SERVICE" /etc/systemd/system/echostream.service
sudo chmod 644 /etc/systemd/system/echostream.service

# Reload systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service
echo "Enabling EchoStream service..."
sudo systemctl enable echostream.service

# Clean up temporary file
rm -f "$TEMP_SERVICE"

echo ""
echo "EchoStream service installed successfully!"
echo ""
echo "Service commands:"
echo "  Start:   sudo systemctl start echostream"
echo "  Stop:    sudo systemctl stop echostream"
echo "  Restart: sudo systemctl restart echostream"
echo "  Status:  sudo systemctl status echostream"
echo "  Logs:    sudo journalctl -u echostream -f"
echo ""
echo "The service will automatically start on boot and restart if it crashes." 