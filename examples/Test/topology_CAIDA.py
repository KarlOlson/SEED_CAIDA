#!/usr/bin/env python3
# encoding: utf-8

from seedemu.layers import Base, Routing, Ebgp, Ibgp, Ospf, PeerRelationship, Dnssec
from seedemu.services import WebService, DomainNameService, DomainNameCachingService
from seedemu.services import CymruIpOriginService, ReverseDomainNameService, BgpLookingGlassService
from seedemu.compiler import Docker, Graphviz
from seedemu.hooks import ResolvConfHook
from seedemu.core import Emulator, Service, Binding, Filter
from seedemu.layers import Router
from seedemu.raps import OpenVpnRemoteAccessProvider
from seedemu.utilities import Makers

from typing import List, Tuple, Dict


###############################################################################
emu     = Emulator()
base    = Base()
routing = Routing()
ebgp    = Ebgp()
ibgp    = Ibgp()
ospf    = Ospf()
web     = WebService()
ovpn    = OpenVpnRemoteAccessProvider()


###############################################################################

#clique
ix100 = base.createInternetExchange(100)

#T1
ix101 = base.createInternetExchange(101)
ix102 = base.createInternetExchange(102)
ix103 = base.createInternetExchange(103)
ix104 = base.createInternetExchange(104)
ix105 = base.createInternetExchange(105)
ix106 = base.createInternetExchange(106)

#T2
ix107 = base.createInternetExchange(107)
ix108 = base.createInternetExchange(108)
ix109 = base.createInternetExchange(109)
ix110 = base.createInternetExchange(110)
ix111 = base.createInternetExchange(111)





###############################################################################
# Create Transit Autonomous Systems 
#Makers.makeTransitAs(base, 3, [100, 103, 104, 105], [(100, 103), (100, 105), (103, 105), (103, 104)]
## Clique ASes (use stub as aggregator)
Makers.makeStubAs(emu, base, 174,   100, [None])
Makers.makeStubAs(emu, base, 1239,  100, [None])
Makers.makeStubAs(emu, base, 1299,  100, [None])
Makers.makeStubAs(emu, base, 2914,  100, [None])
Makers.makeStubAs(emu, base, 3257,  100, [None])
Makers.makeStubAs(emu, base, 3320,  100, [None])
Makers.makeStubAs(emu, base, 3356,  100, [None])

## Tier 1 ASes
Makers.makeTransitAs(base, 1828, [101,100, 102, 103, 105, 106], [(101, 100), (101,103), (101,105), (101,106), (101,102)] )
Makers.makeTransitAs(base, 15830, [102, 100, 101, 103, 104, 105, 106], [(102, 100), (102, 101), (102, 103), (102, 104), (102, 105), (102, 106)] )
Makers.makeTransitAs(base, 9498, [103,100, 101, 105, 106], [(103, 100), (103, 101), (103, 105), (103, 106)] )
Makers.makeTransitAs(base, 39351, [104, 100, 101, 102, 103, 105, 106], [(104, 100), (104, 101), (104, 102), (104, 103), (104, 105), (104, 106)] )
Makers.makeTransitAs(base, 7195, [105,100, 101, 102, 103, 106], [(105, 100), (105, 101), (105, 103), (105, 106), (105, 102)] )
Makers.makeTransitAs(base, 3303, [106,100, 101, 103, 105], [(106, 100), (106, 101), (106, 103), (106, 105)] )

## Tier 2 Transit ASes
Makers.makeTransitAs(base, 29791, [100, 101, 102, 103, 104, 105, 106, 107], [(100, 107),(101, 107),(102, 107),(103, 107),(104, 107), (107,105), (106,107)])
Makers.makeTransitAs(base, 51603, [101, 102, 103, 104, 105], [(101, 102),(101, 103),(101, 104),(101, 105)])
Makers.makeTransitAs(base, 58115, [101, 102, 103, 104, 106, 108], [(108, 102), (108, 104), (108, 106), (108, 103), (108, 101)])
Makers.makeTransitAs(base, 11164, [100, 101, 102, 103, 104, 105, 106, 109], [(109, 100), (109, 101),(109, 102),(109, 103),(109, 104),(109, 105),(109, 106)])
Makers.makeTransitAs(base, 59947, [101, 104, 105, 106, 110], [(110, 101), (110, 104),(110, 105),(110, 106)])

## Tier 2 Extended for Step 8 P2P Links
Makers.makeTransitAs(base, 9583, [100, 101], [(100, 101)])
Makers.makeTransitAs(base, 54825, [100, 102], [(100, 102)])
Makers.makeTransitAs(base, 32787, [100, 103], [(100, 103)])
Makers.makeTransitAs(base, 3491, [100, 106], [(100, 106)])
Makers.makeTransitAs(base, 13335, [100, 101, 102, 103, 104, 105, 106], [(103, 100),(103, 101),(103, 102),(103, 104),(103, 105),(103, 106)])
Makers.makeTransitAs(base, 9304, [100, 101, 102, 103, 105, 106], [(103, 100),(103, 101),(103, 102),(103, 105),(103, 106)])
Makers.makeTransitAs(base, 20940, [100, 101, 102, 103, 104, 105, 106], [(103, 100),(103, 101),(103, 104),(103, 105),(103, 106),(103,102)])
Makers.makeTransitAs(base, 51519, [101, 103, 105, 104], [(104, 101),(104, 103),(104, 105)])
Makers.makeTransitAs(base, 12654, [101, 102, 104, 106], [(104, 101),(104, 102),(104, 106)])
Makers.makeTransitAs(base, 34019, [100, 101, 102, 103, 105, 106], [(106, 100),(106, 101),(106, 102),(106, 103),(106, 105)])
Makers.makeTransitAs(base, 6774, [100, 101, 102, 103, 105, 106], [(106,100), (106, 101),(106, 103),(106, 105), (106,102)])
Makers.makeTransitAs(base, 8758, [101, 102, 103, 105, 106], [(106, 101),(106, 103),(106, 105), (106,102)])
Makers.makeTransitAs(base, 13786, [101, 102, 103, 105, 106], [(105, 101),(105, 102),(105, 103),(105, 106)])




###############################################################################
# Create single-homed stub ASes. "None" means create a host only 

#Clique-stubs
Makers.makeStubAs(emu, base, 34088,  100, [None])
Makers.makeStubAs(emu, base, 146834, 100, [None])
Makers.makeStubAs(emu, base, 50239,  100, [None])
Makers.makeStubAs(emu, base, 39855,  100, [None])
Makers.makeStubAs(emu, base, 37317,  100, [None])
Makers.makeStubAs(emu, base, 50583,  100, [None])

#T1-1828 "Stubs", E.g. Just 1 layer deep ASNs at T1
Makers.makeStubAs(emu, base, 13789,  101, [None])
Makers.makeStubAs(emu, base, 12182,  101, [None])
#Makers.makeStubAs(emu, base, 9583,   101, [None]) # Turned to Transit
Makers.makeStubAs(emu, base, 15695,  101, [None])
Makers.makeStubAs(emu, base, 36086,  101, [None])

#T1 - 15830 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 20940,  102, [None])
#Makers.makeStubAs(emu, base, 54825,  102, [None])
Makers.makeStubAs(emu, base, 16397,  102, [None])
Makers.makeStubAs(emu, base, 24989,  102, [None])
Makers.makeStubAs(emu, base, 26592,  102, [None])

#T1 - 9498 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 32787,  103, [None])
#Makers.makeStubAs(emu, base, 13335,  103, [None])
Makers.makeStubAs(emu, base, 20473,  103, [None])
#Makers.makeStubAs(emu, base, 9304,   103, [None])
#Makers.makeStubAs(emu, base, 20940,  103, [None])

#T1 - 39351 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 51519,   104, [None])
Makers.makeStubAs(emu, base, 15782,   104, [None])
Makers.makeStubAs(emu, base, 203052,  104, [None])
Makers.makeStubAs(emu, base, 39287,   104, [None])
#Makers.makeStubAs(emu, base, 12654,   104, [None])

#T1 - 7195 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 13786,  105, [None])
Makers.makeStubAs(emu, base, 60068,  105, [None])
Makers.makeStubAs(emu, base, 28329,  105, [None])
Makers.makeStubAs(emu, base, 53062,  105, [None])
Makers.makeStubAs(emu, base, 21859,  105, [None])

#T1 - 3303 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 34019,  106, [None])
#Makers.makeStubAs(emu, base, 6774,  106, [None])
#Makers.makeStubAs(emu, base, 8758,  106, [None])
Makers.makeStubAs(emu, base, 12874,  106, [None])
Makers.makeStubAs(emu, base, 39063,  106, [None])

#T2 - 29791 "Stubs"

#T2 - 51603 "Stubs"

#T2 - 58115 "Stubs"

#T2 - 11164 "Stubs"

#T2 - 59947 "Stubs" 


###############################################################################

# To buy transit services from another autonomous system, 
# we will use private peering  

#Clique Peering @ IX100
ebgp.addPrivatePeerings(100, [174],  [1299, 3257, 3320, 3356, 3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [1239], [1299, 3257, 3320, 3356, 3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [1299], [3257, 3320, 3356, 3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [2914], [3257, 3320, 3356], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [3257], [3320, 3356, 3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [3320], [3356, 3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [3356], [3491], PeerRelationship.Peer)

#Clique-Stubs @ IX100 ## may need to use the private peerings method if ab doesnt work.
ebgp.addPrivatePeering (100, 3356, 34088,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 3320, 39855,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 3491, 146834, abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 3257, 37317,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 1299, 50239,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 174,  50583,  abRelationship = PeerRelationship.Provider)

#Clique->T1 @ IX100
ebgp.addPrivatePeerings(100, [174, 3356, 1299, 3257, 2914, 3491], [1828], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [174, 3356, 1299, 3257, 2914, 3491, 3320], [15830], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [174, 1299, 3257, 2914, 3491], [9498], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [174, 1299, 3320], [39351], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [174, 3356, 1299], [7195], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [174, 3356, 3320], [3303], PeerRelationship.Provider)

#T1->T2 @ T1 IX
ebgp.addPrivatePeerings(101, [1828], [9583, 15695, 36086, 13789,12182], PeerRelationship.Provider)
ebgp.addPrivatePeerings(103, [9498], [32787, 13335, 20473, 9304, 20940], PeerRelationship.Provider)
ebgp.addPrivatePeerings(102, [15830], [20940, 54825, 16397, 24989, 26492], PeerRelationship.Provider)
ebgp.addPrivatePeerings(104, [39351], [51519, 203052, 15782, 39287, 12654], PeerRelationship.Provider)
ebgp.addPrivatePeerings(105, [7195], [13786, 60068, 28329, 53062,21859], PeerRelationship.Provider)
ebgp.addPrivatePeerings(106, [3303], [34019, 6774, 8758, 12874, 39063], PeerRelationship.Provider)

#T2-> Stubs  Note: try this method...may need to do abRelationship instead. Need to add some stubs here.
#ebgp.addPrivatePeerings(107, [29791], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(108, [51603], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(109, [58115], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(110, [11164], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(111, [59947], [], PeerRelationship.Provider)

# provider to larger customer P2C Links
ebgp.addPrivatePeering (103, 9498, 1828,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (103, 9304, 1828,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (103, 9498, 15830,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (101, 9583, 13335,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (102, 16397, 54825,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (105, 53062, 13335,  abRelationship = PeerRelationship.Provider)

# Provirder-less Peering (Transit) T2 - 29791
ebgp.addPrivatePeerings(100, [29791], [3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [29791], [13789, 12182], PeerRelationship.Provider)
ebgp.addPrivatePeerings(101, [29791], [36086], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [29791], [15830, 54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [29791], [9498, 9304, 32787, 13335, 20940], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [29791], [39351], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [29791], [13786], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [29791], [3303], PeerRelationship.Peer)

# Provirder-less Peering (Transit) T2 - 58115
ebgp.addPrivatePeerings(101, [58115], [15695], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [58115], [15830], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [58115], [13335, 20940], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [58115], [39351], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [58115], [34019, 8758, 39063], PeerRelationship.Peer)


# Provirder-less Peering (Transit) T2 - 11164
ebgp.addPrivatePeerings(100, [11164], [3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [11164], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [11164], [54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [11164], [32787, 20473, 20940], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [11164], [12654], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [11164], [21859], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [11164], [3303], PeerRelationship.Peer)


# Provirder-less Peering (Transit) T2 - 59947
ebgp.addPrivatePeerings(101, [59947], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [59947], [39351], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [59947], [13786], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [59947], [34019, 8758], PeerRelationship.Peer)


# Provider-less Peering (Transit) T2 - 51603
ebgp.addPrivatePeerings(101, [51603], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [51603], [15830], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [51603], [9498], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [51603], [39351], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [51603], [13786], PeerRelationship.Peer)


# Additional P2P Links


ebgp.addPrivatePeerings(103, [1828], [32787,20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [1828], [54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [1828], [21859, 60068, 28329, 53062], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [1828], [8758], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [39351], [1828, 15695], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [39351], [15830, 54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [39351], [20940, 20473, 32787, 13335, 9498], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [39351], [21859,13786, 60068, 7195, 28329], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [39351], [6774, 39063, 3303, 8758, 34019, 12874], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [9498], [3356], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [9498], [15695], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [9498], [7195, 28329, 60068], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [9498], [39063, 3303, 8758], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [3303], [3491, 3257], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [3303], [9583, 15695, 1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [3303], [20473,32787], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [3303], [7195, 28329, 21859, 60068], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [15830], [15695, 1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [15830], [32787, 20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [15830], [51519], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [15830], [7195, 28329, 60068, 21859], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [15830], [34019, 12874, 39063, 3303, 6774], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [7195], [1828, 15695], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [7195], [54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [7195], [32787, 20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [7195], [39063, 8758], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [13335], [3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [13335], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [13335], [15830], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [13335], [51519], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [13335], [28329, 7195, 13786], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [13335], [6774, 3303, 8758, 34019], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [9304], [3491], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [9304], [9583,15695], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [9304], [54825, 15830, 20940], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [9304], [20473, 13335], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [9304], [60068, 21859, 28329, 7195, 13786], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [9304], [3303, 6774, 34019, 8758, 39063], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [20940], [3320], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [20940], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [20940], [51519], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [20940], [28329, 7195], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [20940], [8758, 3303], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [51519], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [51519], [32787, 20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [51519], [203052], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [51519], [21859], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [12654], [1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [12654], [15830], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [12654], [6774, 3303], PeerRelationship.Peer)

ebgp.addPrivatePeerings(102, [26592], [16397], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [34019], [3320], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [34019], [1828, 15695, 9583], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [34019], [54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [34019], [20940, 32787, 9498, 20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [34019], [28329, 7195], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [34019], [8758, 39063, 6774], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [6774], [3491, 3356], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [6774], [1828, 15695, 9583], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [6774], [54825], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [6774], [20940, 32787, 9498, 20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [6774], [7195, 28329, 60068], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [6774], [39063, 8758, 12874], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [8758], [15695], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [8758], [20473, 32787], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [8758], [28329,21859], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [8758], [39063], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [13786], [36086, 1828], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [13786], [54825, 15830], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [13786], [32787, 20940, 9498, 20473], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [13786], [21859, 60068], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [13786], [8758, 34019, 39063, 3303, 6774], PeerRelationship.Peer)

ebgp.addPrivatePeerings(105, [28329], [21859, 60068], PeerRelationship.Peer)

ebgp.addPrivatePeerings(105, [53062], [60068], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [32787], [3320, 3257], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [54825], [3356], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [9583], [3257], PeerRelationship.Peer)


# Additional P2C Links


###############################################################################

# Add layers to the emulator
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(ebgp)
emu.addLayer(ibgp)
emu.addLayer(ospf)
emu.addLayer(web)

# Save it to a component file, so it can be used by other emulators
emu.dump('base-component.bin')

# Uncomment the following if you want to generate the final emulation files
emu.render()
emu.compile(Docker(), './output')

