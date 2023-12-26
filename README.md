# Hetzner Dynamic IP FW Rule Updater

## Setup

```bash
# install python 3.12
apt install python3.12

# go to project directory
cd /to/project/directory

# setup venv
python3.12 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt

# edit config file
cp config_example.yml config.yml
vim config.yml

# optional
cp hetzner-dynamic-ip-fw-rule-updater.server /etc/systemd/system/
```
