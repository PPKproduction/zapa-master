#!/usr/bin/env bash

set -e

PROGRAM_FILE_PATH="/opt/zapa-master/master.py"
CONF_FILE_PATH="/etc/zapa-master.conf.yaml"
SYSTEMD_UNIT_FILE_PATH="/etc/systemd/system/zapa-master.service"

if [ "$1" = '-u' -o "$1" = '--uninstall' ]; then
    echo -e "\033[1;37mUninstalling...\033[0m"

    echo " - stopping the service"
    sudo systemctl stop zapa-master.service

    echo " - removing $(dirname "${PROGRAM_FILE_PATH}")"
    sudo rm -rf "$(dirname "${PROGRAM_FILE_PATH}")"

    echo " - removing config file ${CONF_FILE_PATH}"
    sudo rm -f "${CONF_FILE_PATH}"

    echo " - removing systemd unit file ${SYSTEMD_UNIT_FILE_PATH}"
    sudo rm -f "${SYSTEMD_UNIT_FILE_PATH}"

    echo " - reloading systemd daemon"
    sudo systemctl daemon-reload

    echo "Uninstallation complete (except for python dependencies)."
    exit 0
else
    echo -e "\033[1;37mInstalling...\033[0m"
fi

# install dependencies
echo " - installing python dependencies (assuming RPi python stuff is already installed)"
sudo pip install pyyaml pycryptodome adafruit-circuitpython-rfm9x

# install the program
echo " - installing program to ${PROGRAM_FILE_PATH}"
sudo mkdir -p "$(dirname "${PROGRAM_FILE_PATH}")"
sudo cp /home/pi/Downloads/zapamaster/master.py "${PROGRAM_FILE_PATH}"

# place configuration file
echo " - installing config file to ${CONF_FILE_PATH}"
sudo tee "${CONF_FILE_PATH}" >/dev/null <<EOF
# replace ... with an ASCII string 16, 24, or 32 characters long
secret: ...
# list the slave addresses this master manages
slaves:
 - ... # replace ... with address, e.g. 0x01
 - ...
# delay before an ack is sent back (in seconds)
# if not specified, default is 0.1
ack_delay: 0.1
# number of retransmissions before giving up on receiving an ack
# if not specified, default is 8
ack_retries: 8
# minimum waiting time (in seconds) for an ack before retransmitting
# at runtime is chosen randomly between ack_wait and 2 * ack_wait
# if not specified, default is 0.25
ack_wait: 0.25
# trasmission power between (and including) 5 and 20
# if not specified, default is 13
tx_power: 13
EOF

sudo nano ${CONF_FILE_PATH}

# place systemd unit file
echo " - installing systemd unit file to ${SYSTEMD_UNIT_FILE_PATH}"
sudo tee "${SYSTEMD_UNIT_FILE_PATH}" >/dev/null <<EOF
[Unit]
Description = Zapa Beton radio master daemon
After = network.target

[Service]
Type = simple
ExecStart = /usr/bin/python "${PROGRAM_FILE_PATH}" "${CONF_FILE_PATH}"
TimeoutStopSec = 10
# Do not restart when the program exitted due to error in configuration.
RestartPreventExitStatus = 78
Restart = on-failure
RestartSec = 5
# Uncomment the following lines to run the service as the installing user/group.
#User = $(id -un)
#Group = $(id -gn)

[Install]
WantedBy = multi-user.target
EOF

# reload systemd
echo " - reolading systemd deaemon"
sudo systemctl daemon-reload

echo "Installation complete."
echo -e "\033[1;31mThings you sould do now:\033[0m"
echo -e "   * edit the config file ${CONF_FILE_PATH}"
echo -e "   * start the service by running: systemctl start zapa-master.service"
echo -e "   * check on the service by running systemctl status zapa-master.service and/or via journalctl (e.g. journalctl -fu zapa-master.service)"
echo -e "   * if everything is ok, enable the service startup at system startup by running: systemctl enable zapa-master.service"



sudo systemctl start zapa-master.service
sudo systemctl enable zapa-master.service
