import psutil
import netifaces
import socket


def get_default_gateway():
  # 获取默认网关信息
  gws = netifaces.gateways()
  default_gateway = gws.get('default', {})
  if netifaces.AF_INET in default_gateway:
    gateway, iface = default_gateway[netifaces.AF_INET]
    return gateway, iface
  return None, None


def get_active_interface_details():
  # 获取所有网卡详细信息
  net_interfaces = psutil.net_if_addrs()
  gateway, iface = get_default_gateway()

  if iface and iface in net_interfaces:
    # 获取网卡地址信息
    details = net_interfaces[iface]
    ip_info = [addr.address for addr in details if addr.family == socket.AF_INET]
    mac_info = [addr.address for addr in details if addr.family == psutil.AF_LINK]
    return {
      "interface": iface,
      "gateway": gateway,
      "ip_address": ip_info[0] if ip_info else "N/A",
      "mac_address": mac_info[0] if mac_info else "N/A",
    }
  return None


if __name__ == "__main__":
  info = get_active_interface_details()
  if info:
    print(f"Active Interface: {info['interface']}")
    print(f"Default Gateway: {info['gateway']}")
    print(f"IP Address: {info['ip_address']}")
    print(f"MAC Address: {info['mac_address']}")
  else:
    print("No active interface found.")
