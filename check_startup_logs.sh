#!/bin/bash

echo "=== EchoStream Startup Logs Analysis ==="
echo "Time: $(date)"
echo

# Get the most recent startup logs
echo "=== Recent Startup Logs ==="
journalctl -u echostream --since "1 hour ago" | grep -E "(ECHOSTREAM STARTUP|GPIO|Channel.*added|Added.*channels)" | tail -20

echo
echo "=== GPIO Initialization Logs ==="
journalctl -u echostream --since "1 hour ago" | grep -E "(init_gpio|pinctrl|GPIO.*pin|Failed.*GPIO)" | tail -15

echo
echo "=== Channel Configuration Logs ==="
journalctl -u echostream --since "1 hour ago" | grep -E "(Channel.*GPIO|Physical Pin|GPIO Number)" | tail -15

echo
echo "=== Error and Warning Logs ==="
journalctl -u echostream --since "1 hour ago" | grep -E "(ERROR|WARNING|Failed)" | tail -10

echo
echo "=== Current Service Status ==="
systemctl status echostream --no-pager -l
