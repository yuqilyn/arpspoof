import subprocess
import re


def get_default_gateway():
    try:
        # 执行 ipconfig 命令并获取输出
        ipconfig_output = subprocess.check_output("ipconfig", encoding="utf-8", errors="ignore")

        # 定义正则表达式以匹配默认网关的部分
        gateway_pattern = re.compile(r"Default Gateway[ .]+: ([\d\.]+)")

        # 在 ipconfig 输出中查找所有匹配的默认网关
        gateways = gateway_pattern.findall(ipconfig_output)

        # 查找 Ethernet0 的默认网关
        gateway = None
        adapter_found = False
        lines = ipconfig_output.splitlines()

        for line in lines:
            # 检查是否遇到以太网适配器信息
            if "Ethernet adapter Ethernet0" in line:
                adapter_found = True
            if adapter_found and "Default Gateway" in line:
                match = re.search(r"Default Gateway[ .]+: ([\d\.]+)", line)
                if match:
                    gateway = match.group(1)
                    break

        if gateway:
            return gateway
        else:
            return None

    except subprocess.CalledProcessError as e:
        return f"Error running ipconfig: {e}"


if __name__ == "__main__":
    gateway = get_default_gateway()
    print(f"Default Gateway for Ethernet adapter: {gateway}")
