import subprocess
import re


def get_wifi_gateway():
  try:
    # Execute the ipconfig command and get the output using GBK encoding to avoid UnicodeDecodeError
    ipconfig_output = subprocess.check_output("ipconfig", encoding="gbk", errors='ignore')

    # Initialize variables to find the correct adapter's gateway
    wifi_gateway = None
    adapter_found = False

    # Split the output into lines for easier processing
    lines = ipconfig_output.splitlines()

    for i, line in enumerate(lines):
      # Check if the Wireless LAN adapter WLAN section is found
      if "Wireless LAN adapter WLAN" in line:
        adapter_found = True

      # If the adapter is found and the line contains "Default Gateway", try to match it
      if adapter_found and "Default Gateway" in line:
        match = re.search(r"Default Gateway[ .]+: ([\d\.]+)", line)
        if match:
          wifi_gateway = match.group(1)
          break
        # If no match, check the next line for the actual gateway
        elif i + 1 < len(lines):
          next_line = lines[i + 1]
          next_match = re.search(r"([\d\.]+)", next_line)  # Match IPv4 address
          if next_match:
            wifi_gateway = next_match.group(1)
            break

    # Return the found gateway or an appropriate message if not found
    if wifi_gateway:
      return wifi_gateway
    else:
      return "No default gateway found for the wireless adapter."

  except subprocess.CalledProcessError as e:
    return f"Error running ipconfig: {e}"


if __name__ == "__main__":
  gateway = get_wifi_gateway()
  print(f"Wi-Fi Default Gateway: {gateway}")
