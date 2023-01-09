import os, sys, time, socket, struct, fcntl, re
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import pcap

class Sniffing:
    def __init__(self, iface=None):
        self.args = {
            "interface": iface
            }
        self.clients_aps = []
        self.aps = []
        self.DN = open(os.devnull, 'w')
        self.lock = Lock()
        self.monitor_on = False
        self.mon_iface = self.get_mon_iface(self.args["interface"])
        self.iface = self.mon_iface
        self.monchannel = 1
        self.exit = False

    def get_mon_iface(self, iface):
        if iface:
            if self.check_monitor(iface):
                self.monitor_on = True
                return iface

    def check_monitor(self, iface):
        try:
            proc = Popen(['iwconfig', iface], stdout=PIPE, stderr=PIPE)
            data =  proc.communicate()
            if "Mode:Monitor" in data[0].decode():
                return True
            elif "No such device" in data[1].decode():
                print("Interface not found")
                return False
            print("Interface is not in mode monitor")
            self.start_mon_mode(iface)
            return True
        except OSError:
            print('Could not execute "iwconfig"')
            return False

    def start_mon_mode(self, interface):
        print(f'Starting monitor mode off {interface}')
        try:
            os.system('ifconfig %s down' % interface)
            os.system('iwconfig %s mode monitor' % interface)
            os.system('ifconfig %s up' % interface)
            return interface
        except Exception:
            print('Could not start monitor mode')
            self.exit = True

    def channel_hop(self, mon_iface, args):
        channel_num = 0
        max_channel = 13
        err = None

        while True:
            channel_num +=1
            if channel_num > max_channel:
                channel_num = 1
            with self.lock:
                self.monchannel = str(channel_num)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', self.monchannel], stdout=self.DN, stderr=PIPE)
                for line in proc.communicate()[1].decode().split('\n'):
                    if len(line) > 2:
                        err = f'Channel hopping failed: {line}'
                if self.exit:
                    return
                self.output(err, self.monchannel)
                time.sleep(1)
            except OSError:
                print('Could not execute "iw"')
                self.exit = True
                return

    def output(self, err, monchannel):
        os.system('clear')
        if err:
            print(err)
        else:
            print(f'{self.mon_iface} channel: {monchannel}\n')

        if len(self.aps) > 0:
            print('\n      BSSID            PWR Beacons CH   ESSID')
            with self.lock:
                for ap in self.aps:
                    print(f'[*] {ap["bssid"]}  {ap["PWR"]}  {ap["Beacons"]}      {ap["ap_channel"].ljust(2)}  {ap["essid"]}')

        print('')

        if len(self.clients_aps) > 0:
            print('            BSSID         STATION          PWR')
        # Print the clients list
            with self.lock:
                for ca in self.clients_aps:
                    print(f"[*] {ca['bssid']}  {ca['station']}  {ca['PWR']}")


    def sniff(self):
        sniffer = pcap.pcap(name=self.mon_iface, promisc=True, immediate=True, timeout_ms=50)

        for ts, pkt in sniffer:


            frame_control = pkt[0x18]

            if frame_control == 0x80: #chk beacon frame
                bssid_h = pkt[0x28:0x28+6].hex()
                bssid = ':'.join(bssid_h[i:i + 2] for i in range(0, 12, 2))

                pwr = struct.unpack("b",struct.pack("B",pkt[0x12]))[0]

                #tag
                essid = None
                ch = None

                tag_offset = 0x3c
                while tag_offset < len(pkt):
                    tag_num = pkt[tag_offset]
                    tag_len = pkt[tag_offset+1]

                    #print(tag_num, tag_len)
                    if tag_num == 0:
                        essid = pkt[tag_offset+2:tag_offset+2+tag_len] #essid
                    elif tag_num == 3:
                        ch = pkt[tag_offset+2] #channel

                    tag_offset += tag_len + 2

                    if essid and ch :
                        break

                skp = False
                for ap in self.aps:
                    if ap["bssid"] == bssid.upper():
                        with self.lock:
                            ap["PWR"] = str(pwr)
                            ap["Beacons"] = str(int(ap["Beacons"])+1)
                        skp = True
                        break

                if not skp:
                    with self.lock:
                        self.aps.append({
                                "bssid": bssid.upper(),
                                "PWR" : str(pwr),
                                "Beacons" : "1",
                                "ap_channel": str(ch),
                                "essid": essid.decode()})


            #chk Probe request, Probe response
            elif frame_control == 0x40 or frame_control == 0x50:
                bssid_h = pkt[0x1c:0x1c+6].hex()
                bssid = ':'.join(bssid_h[i:i + 2] for i in range(0, 12, 2))
                station_h = pkt[0x22:0x22+6].hex()
                station = ':'.join(station_h[i:i + 2] for i in range(0, 12, 2))
                if bssid_h == "ffffffffffff":
                    bssid = '(not associated)'

                if frame_control == 0x50:
                    bssid, station = station, bssid

                pwr = struct.unpack("b",struct.pack("B",pkt[0x12]))[0]

                skpaa = False
                for cp in self.clients_aps:
                    if cp["station"] == station.upper():
                        with self.lock:
                            cp["PWR"] = str(pwr)
                            skp = True
                            break


                if not skp:
                    with self.lock:
                        self.clients_aps.append({
                                "bssid": bssid.upper(),
                                "station": station.upper(),
                                "PWR" : str(pwr)})

    def run(self):
        th = Thread(target=self.channel_hop, args=(self.mon_iface, self.args))
        th.daemon = True
        th.start()

        self.sniff()

if __name__ == "__main__":
    if os.geteuid():
        print("Please run as root")
    else:

        if len(sys.argv) != 2:
            print("Usage: sudo python3 airodump.py <interface>")
            sys.exit()

        iface = sys.argv[1]

        if iface != "" :
            sn = Sniffing(iface=iface)
            sn.run()
