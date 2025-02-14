import asyncio
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, ObjectIdentity,\
    CommunityData, UdpTransportTarget, ContextData, bulk_cmd #ObjectType
from pysnmp.hlapi.v3arch import CommunityData
from collections import defaultdict

class BulkCollector:
    def __init__(self, devices, community='public', port=161, 
                 timeout=2, max_concurrent=200, bulk_size=50):
        self.devices = devices
        self.community = community
        self.port = port
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.bulk_size = bulk_size
        self.oids = (
            ObjectIdentity(""),
            # LLDP (1.0.8802.1.1.2.1.4.1)
            ObjectIdentity("1.0.8802.1.1.2.1.4.1.1"),  # lldpRemSysName
            ObjectIdentity("1.0.8802.1.1.2.1.4.1.2"),  # lldpRemPortId
            
            # ARP (1.3.6.1.2.1.4.22.1)
            ObjectIdentity("1.3.6.1.2.1.4.22.1.2"),  # ipNetToMediaPhysAddress
            ObjectIdentity("1.3.6.1.2.1.4.22.1.3"),  # ipNetToMediaNetAddress
            
            # Routing (1.3.6.1.2.1.4.24.4.1)
            ObjectIdentity("1.3.6.1.2.1.4.24.4.1.1"),  # ipCidrRouteDest
            ObjectIdentity("1.3.6.1.2.1.4.24.4.1.2"),  # ipCidrRouteMask
            ObjectIdentity("1.3.6.1.2.1.4.24.4.1.3"),  # ipCidrRouteNextHop
        )
        self.results = defaultdict(dict)

    async def _fetch_device(self, device):
        async with self.semaphore:
            snmp_engine = SnmpEngine()
            try:
                udp_target = await UdpTransportTarget.create(('192.168.10.100', 161), timeout=1, retries=5, tagList='')
                iterator = await bulk_cmd(
                    snmp_engine,
                    CommunityData(self.community),
                    udp_target,
                    ContextData(),
                    0, self.bulk_size,
                    *self.oids,
                    lexicographicMode=False,
                    lookupMib=False  # Skip MIB resolution for performance
                )

                device_data = []
                async for (errorIndication, errorStatus, 
                          errorIndex, varBinds) in iterator:
                    if errorIndication:
                        print(f"{device} Error: {errorIndication}")
                        break
                    if errorStatus:
                        print(f"{device} Error: {errorStatus.prettyPrint()}")
                        break

                    # Process varBinds with minimal memory allocation
                    device_data.extend(
                        (oid.prettyPrint(), value.prettyPrint())
                        for oid, value in varBinds
                    )

                self.results[device] = self._structure_data(device_data)
                
            except Exception as e:
                print(f"{device} Critical failure: {str(e)}")
            finally:
                snmp_engine.close_dispatcher()

    def _structure_data(self, raw_data):
        """Convert flat OID-value pairs to structured records"""
        structured = {'lldp': [], 'arp': [], 'routes': []}
        
        for oid, value in raw_data:
            # OID pattern matching without MIB resolution
            if '1.0.8802.1.1.2.1.4.1' in oid:
                structured['lldp'].append((oid.split('.')[-2], value))
            elif '1.3.6.1.2.1.4.22.1' in oid:
                structured['arp'].append((oid.split('.')[-2], value))
            elif '1.3.6.1.2.1.4.24.4.1' in oid:
                structured['routes'].append((oid.split('.')[-2], value))
        
        return structured

    async def run(self):
        """Main entry point with controlled concurrency"""
        tasks = [self._fetch_device(dev) for dev in self.devices]
        await asyncio.gather(*tasks)
        return dict(self.results)

# Usage
async def main(devices, net_size):
    collector = BulkCollector(
        devices=devices,
        community='private',
        timeout=1,
        max_concurrent=net_size,
        bulk_size=100
    )
    
    start = time.monotonic()
    results = await collector.run()
    duration = time.monotonic() - start
    
    print(f"Collected {len(results)} devices in {duration:.2f} seconds")
    print(f"Memory usage: {asizeof.asizeof(results)/1024/1024:.2f} MB")

devices = ['192.168.10.100']
net_size = 100

if __name__ == "__main__":
    import time
    from pympler import asizeof  #memory analysis
    
    asyncio.run(main(devices, net_size))
