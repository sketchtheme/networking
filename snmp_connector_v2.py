from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, ObjectIdentity,\
    CommunityData, UdpTransportTarget, ContextData, ObjectType, bulk_cmd
from pysnmp.entity.rfc3413 import cmdgen
from multiprocessing import Pool, cpu_count
import asyncore
import time

class BulkSNMPCollector:
    def __init__(self, devices, community='public', port=161, timeout=2, retries=1):
        self.devices = devices
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.results = {}
        self.oids = (
            # LLDP Neighbors
            '1.0.8802.1.1.2.1.4.1.1',  # lldpRemSysName
            '1.0.8802.1.1.2.1.4.1.2',  # lldpRemPortId
            # ARP Table
            '1.3.6.1.2.1.4.22.1.2',    # ipNetToMediaPhysAddress
            '1.3.6.1.2.1.4.22.1.3',    # ipNetToMediaNetAddress
            # Routing Table
            '1.3.6.1.2.1.4.24.4.1.1',  # ipCidrRouteDest
            '1.3.6.1.2.1.4.24.4.1.2',  # ipCidrRouteMask
            '1.3.6.1.2.1.4.24.4.1.3',  # ipCidrRouteNextHop
        )

    def _bulk_query(self, device):
        """Low-level SNMP bulk GET operation with connection reuse"""
        iterator = bulk_cmd(
            SnmpEngine(),
            CommunityData(self.community),
            UdpTransportTarget((device, self.port), timeout=self.timeout, retries=self.retries),
            ContextData(),
            0, 50,  # Non-repeaters and max-repetitions
            *[ObjectType(ObjectIdentity(oid)) for oid in self.oids],
            lexicographicMode=False,
            lookupMib=False  # Skip MIB resolution for performance
        )

        device_data = []
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication:
                    print(f"{device} Error: {errorIndication}")
                    break
                if errorStatus:
                    print(f"{device} Error: {errorStatus.prettyPrint()}")
                    break
                
                # Process varBinds in minimal memory footprint
                device_data.extend([
                    (varBind[0].prettyPrint(), varBind[1].prettyPrint())
                    for varBind in varBinds
                ])
        except Exception as e:
            print(f"{device} Exception: {str(e)}")
        
        return (device, device_data)

    def _result_handler(self, result):
        """Handle results with minimal locking"""
        device, data = result
        self.results[device] = data

    def run(self):
        """Parallel execution with process pool"""
        with Pool(processes=min(cpu_count()*2, len(self.devices))) as pool:
            for device in self.devices:
                pool.apply_async(self._bulk_query, (device,), callback=self._result_handler)
            pool.close()
            pool.join()

        return self.results


if __name__ == "__main__":
    devices = open("D:\\projects\\CapsulePy\\test2\\connectors\\devices.txt")
    collector = BulkSNMPCollector(
        devices=devices,
        community='private',
        timeout=1,
        retries=0
    )
    
    start_time = time.time()
    results = collector.run()
    print(f"Collected {len(results)} devices in {time.time() - start_time:.2f} seconds")
