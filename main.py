from textwrap import indent
import requests
import yaml
import time
import logging
from typing import Any
from hcloud._client import Client as hcc
from hcloud import _exceptions as hce
from hcloud.firewalls.domain import FirewallRule
# pipreqs . --force


# setup logging
logging.basicConfig(
  format='%(asctime)s [%(filename)s:%(lineno)d] %(levelname)s: %(message)s',
  level=logging.INFO
)


def get_ipv4() -> str:
  ident_me_ipv4: list[str] = ["https://v4.ident.me", "https://v4.tnedi.me"]
  ipv4_address: str = ""
  for ident_me in ident_me_ipv4:
    try:
      ipv4_address = requests.get(ident_me).text
      if ipv4_address != "":
        return ipv4_address
    except requests.exceptions.ConnectionError:
      logging.error(f"No IPv4 found with {ident_me}.")
  # If no IPv4 can be found the container will exit with a non zero exit code.
  # The reason is that it probably is a configuration error.
  exit(1)


def get_ipv6() -> str:
  ident_me_ipv6: list[str] = ["https://v6.ident.me", "https://v6.tnedi.me"]
  ipv6_address: str = ""
  for ident_me in ident_me_ipv6:
    try:
      ipv6_address = requests.get(ident_me).text
      if ipv6_address != "":
        return ipv6_address
    except requests.exceptions.ConnectionError:
      logging.error(f"No IPv6 found with {ident_me}.")
  # If no IPv6 can be found the container will exit with a non zero exit code.
  # The reason is that it probably is a configuration error.
  exit(1)


def hdns_record_create_or_update(
  headers: dict[str,str],
  ip_address: str,
  record_type: str,
  record_name: str,
  record_id: str,
  zone_id: str
) -> int:
  """Creates or updates a record in the Hetzner DNS Console"""
  data: dict[str, Any] = {
    "value": ip_address,
    "ttl": 120,
    "type": record_type,
    "name": record_name,
    "zone_id": zone_id
  }
  if record_id:
    response_status_code: int = requests.put(url=f"https://dns.hetzner.com/api/v1/records/{record_id}", headers=headers, json=data).status_code
    return response_status_code
  response_status_code: int = requests.post(url="https://dns.hetzner.com/api/v1/records", headers=headers, json=data).status_code
  return response_status_code


if __name__ == "__main__":
  with open("config.yml", 'r') as config_file:
    config_content: dict[str,Any] = yaml.safe_load(config_file)
  # load all vars from config.yml
  ip_version: str = config_content["ip_version"].lower()
  wait_time: int = int(config_content["wait_time"])
  hcloud_token: str = config_content["hcloud"]["token"]
  hcloud_firewall_name: str = config_content["hcloud"]["firewall_name"]
  # load all rules from the config.yml in a list in form of objects
  hcloud_firewall_rules: list[Any] = []
  for rule in config_content["hcloud"]["firewall_rules"]:
    hcloud_firewall_rules.append(FirewallRule(
      direction=rule["direction"],
      protocol=rule["protocol"],
      port=str(rule["port"]),
      source_ips=["127.0.0.1/32"],
      description=rule["description"]
    ))
  hdns_headers: dict[str,str] = {
    'Auth-API-Token': str(config_content["hdns"]["token"]),
    'Content-Type': 'application/json'
  }
  hdns_zone_name: str = config_content["hdns"]["zone_name"]
  hdns_record_name: str = config_content["hdns"]["record_name"]
  # global runtime vars
  hdns_zone_id: str = ""
  hdns_a_record_id: str = ""
  hdns_aaaa_record_id: str = ""
  ipv4_address: str = ""
  ipv6_address: str = ""


  # create client for the hetzner cloud
  # sadly I can't catch a faulty token at this point in the code
  hcloud_client = hcc(token=hcloud_token)
  # get the hcloud_firewall variable set before calling the timed function to reduce traffic
  # if there isn't a firewall with the right name already it creates a new empty firewall
  # because the logic for rules will be later called, while updating the rule
  try:
    hcloud_firewall = hcloud_client.firewalls.get_by_name(hcloud_firewall_name)
    if not hcloud_firewall:
      logging.warning("Couldn't finde firewall, creating new empty firewall.")
      hcloud_client.firewalls.create(name=hcloud_firewall_name)
      # the line below seems to be needed because hcloud_client.firewalls.create() doesn't return a id,
      # which is later needed by hcloud_client.firewalls.set_rules()
      hcloud_firewall = hcloud_client.firewalls.get_by_name(hcloud_firewall_name)
  except hce.APIException:
    logging.critical("Unable to authenticate at Hetzner Cloud.")
    exit(code=1)


  # get hdns_zone_id
  if hdns_zone_id == "":
    response_json: dict[Any,Any] = requests.get(url="https://dns.hetzner.com/api/v1/zones", headers=hdns_headers).json()
    for zone in response_json["zones"]:
      if zone["name"] == hdns_zone_name:
        hdns_zone_id = zone["id"]
        break
    if hdns_zone_id == "":
      logging.critical("Zone name not found.")
      exit(code=1)


  def run():
    """this function contains the code that should be executed every 10 minutes"""
    global ipv4_address
    global ipv6_address
    global hdns_a_record_id
    global hdns_aaaa_record_id
    global hdns_zone_id

    # get the current IPv4 and/or IPv6
    match ip_version:
      case "v4":
        new_ipv4_address: str = get_ipv4()
        if new_ipv4_address == ipv4_address:
          logging.info("No ip change detected.")
          return
        else:
          ipv4_address = new_ipv4_address
      case "v6":
        new_ipv6_address: str = get_ipv6()
        if new_ipv6_address == ipv6_address:
          logging.info("No ip change detected.")
          return
        else:
          ipv6_address = new_ipv6_address
      case "dualstack":
        new_ipv4_address: str = get_ipv4()
        new_ipv6_address: str = get_ipv6()
        if new_ipv4_address == ipv4_address and new_ipv6_address == ipv6_address:
          logging.info("No ip change detected.")
          return
        else:
          ipv4_address = new_ipv4_address
          ipv6_address = new_ipv6_address
    logging.info(f"new IPs: {ipv4_address}, {ipv6_address}")


    # update Hetzner cloud firewall
    # convert single IPs to IPs with subnet mask
    ip_addresses: list[str] = []
    if ipv4_address:
      ip_addresses.append(f"{ipv4_address}/32")
    if ipv6_address:
      ip_addresses.append(f"{ipv6_address}/128")
    # update firewall rules with new subnets
    for rule in hcloud_firewall_rules:
      rule.source_ips = ip_addresses

    # update/create firewall
    #TODO CRITICAL: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
    try:
        hcloud_client.firewalls.set_rules(firewall=hcloud_firewall, rules=hcloud_firewall_rules) # type: ignore
        logging.info("Updated Hetzner Cloud firewall.")
    except Exception as e:
      logging.critical(e)
      exit(code=1)


    # update dyndns record
    # try to get hdns_record_id
    # I habe put this in the looping function to have a easy solution in the case that the record didn't exist on first run.
    if hdns_a_record_id == "" and hdns_aaaa_record_id == "":
      response_json: dict[Any,Any] = requests.get(url=f"https://dns.hetzner.com/api/v1/records?zone_id={hdns_zone_id}", headers=hdns_headers).json()
      for record in response_json["records"]:
        if ipv4_address and record["name"] == hdns_record_name and record["type"] == "A":
          hdns_a_record_id = record["id"]
          logging.info("Updated A record id.")
        if ipv6_address and record["name"] == hdns_record_name and record["type"] == "AAAA":
          hdns_aaaa_record_id = record["id"]
          logging.info("Updated AAAA record id.")

    # create or update dns records
    if ipv4_address:
      status_code = hdns_record_create_or_update(
        headers=hdns_headers,
        ip_address=ipv4_address,
        record_type="A",
        record_name=hdns_record_name,
        record_id=hdns_a_record_id,
        zone_id=hdns_zone_id
      )
      logging.info(f"IPv4 create/update status code: {status_code}")
    if ipv6_address:
      status_code = hdns_record_create_or_update(
        headers=hdns_headers,
        ip_address=ipv6_address,
        record_type="AAAA",
        record_name=hdns_record_name,
        record_id=hdns_aaaa_record_id,
        zone_id=hdns_zone_id
      )
      logging.info(f"IPv6 create/update status code: {status_code}")


  # run the loop for updating the records
  while True:
    try:
      run()
      time.sleep(wait_time)
    except:
      logging.info("exit")
      exit(code=0)
