import asyncio
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, ObjectIdentity,\
    CommunityData, UdpTransportTarget, ContextData, bulk_cmd, ObjectType
from collections import defaultdict

def safe_pretty(oid, value):
    try:
        oid_str = oid.prettyPrint()
    except Exception as e:
        oid_str = f"<Error: {e}>"
    try:
        value_str = value.prettyPrint()
    except Exception as e:
        value_str = f"<Error: {e}>"
    return oid_str, value_str

def chunk_list(lst, chunk_size):
    """Yield successive chunk_size-sized chunks from lst."""
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i+chunk_size]

class BulkCollector:
    def __init__(self, devices, community='huawei', port=161, 
                 timeout=2, max_concurrent=200, bulk_size=50, oids_chunk_size=3):
        if isinstance(devices, str):
            devices = [devices]
        self.devices = devices
        self.community = community
        self.port = port
        self.timeout = timeout
        self.oids_chunk_size = oids_chunk_size  # Number of OIDs per bulk request
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.bulk_size = bulk_size
        self.oids = (
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.2.0")), 
            # LLDP (1.0.8802.1.1.2.1.4.1)
            ObjectType(ObjectIdentity("1.0.8802.1.1.2.1.4.1.1")),  # lldpRemSysName
            ObjectType(ObjectIdentity("1.0.8802.1.1.2.1.4.1.2")),  # lldpRemPortId
            
            # ARP (1.3.6.1.2.1.4.22.1)
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.22.1.2")),  # ipNetToMediaPhysAddress
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.22.1.3")),  # ipNetToMediaNetAddress
            
            # Routing (1.3.6.1.2.1.4.24.4.1)
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.24.4.1.1")),  # ipCidrRouteDest
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.24.4.1.2")),  # ipCidrRouteMask
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.24.4.1.3")),  # ipCidrRouteNextHop
        )
        self.results = defaultdict(dict)

    async def _fetch_device(self, device):
        async with self.semaphore:
            snmp_engine = SnmpEngine()
            try:
                udp_target = await UdpTransportTarget.create(
                    (device, self.port),
                    timeout=self.timeout,
                    retries=5,
                    tagList=''
                )
                # Convert the tuple of OIDs into a list for grouping:
                oids_list = list(self.oids)
                device_data = []
                # Process OIDs in groups
                for group in chunk_list(oids_list, self.oids_chunk_size):
                    start_call = time.monotonic()
                    # Await the bulk_cmd for the current group
                    result = await bulk_cmd(
                        snmp_engine,
                        CommunityData(self.community),
                        udp_target,
                        ContextData(),
                        0, self.bulk_size,
                        *group,
                        lexicographicMode=False,
                        lookupMib=False  # Skip MIB resolution for performance
                    )
                    round_trip = time.monotonic() - start_call
                    print(f"{device} Round-trip time for group {group}: {round_trip:.3f} seconds")
                    
                    errorIndication, errorStatus, errorIndex, varBinds = result
                    if errorIndication:
                        print(f"{device} Error: {errorIndication}")
                        continue
                    if errorStatus:
                        print(f"{device} Error: {errorStatus.prettyPrint()}")
                        continue
                    # Process varBinds using safe_pretty
                    device_data.extend(safe_pretty(oid, value) for oid, value in varBinds)
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
        community='huawei_router',
        timeout=1,
        max_concurrent=net_size,
        bulk_size=100,
        oids_chunk_size=2
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

# Router SNMP/4/WARMSTART:OID 1.3.6.1.6.3.1.1.5.2
# Router DS/4/DATASYNC_CFGCHANGE:OID 1.3.6.1.4.1.2011.5.25.191.3.1
