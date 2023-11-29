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
import argparse
import random

#Process command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-d', type=int, required = False,
                    help="proxy deployment percentage")
FLAGS = parser.parse_args()
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
# 5 Transit ASes -> 100-105
# 12 Stub ASes -> 106-117
# Total num ASes of 17
total_ASes =  53
if FLAGS.d:       
  dep_percentage = FLAGS.d/100
  true_count = int(total_ASes * dep_percentage)
  false_count = total_ASes - true_count
  proxy = [True] * true_count + [False] * false_count
  #random.seed(0) 
  random.shuffle(proxy)
else: # no percentage specified, do not deploy proxy
  proxy = [False] * total_ASes
  
###############################################################################





###############################################################################
# Create Transit Autonomous Systems 
#Makers.makeTransitAs(base, 3, [100, 103, 104, 105], [(100, 103), (100, 105), (103, 105), (103, 104)]
## Clique ASes (use stub as aggregator)
Makers.makeStubAs(emu, base, 131,   100, [None], proxy[47] )
#Makers.makeStubAs(emu, base, 1239,  100, [None])
Makers.makeStubAs(emu, base, 132,  100, [None], proxy[48] )
Makers.makeStubAs(emu, base, 127,  100, [None], proxy[49] )
Makers.makeStubAs(emu, base, 128,  100, [None], proxy[50] )
Makers.makeStubAs(emu, base, 129,  100, [None], proxy[51] )
Makers.makeStubAs(emu, base, 133,  100, [None], proxy[52] )

## Tier 1 ASes
Makers.makeTransitAs(base, 134, [101,100,102, 103, 105, 106], [(101, 100), (101,103), (101,105), (101,106), (101,102)], proxy[0] )
Makers.makeTransitAs(base, 135, [102, 100, 101, 103, 104, 105, 106], [(102, 100), (102, 101), (102, 103), (102, 104), (102, 105), (102, 106)], proxy[1] )
Makers.makeTransitAs(base, 136, [103,100, 101, 105, 106], [(103, 100), (103, 101), (103, 105), (103, 106)], proxy[2] )
Makers.makeTransitAs(base, 137, [104, 100, 101, 102, 103, 105, 106], [(104, 100), (104, 101), (104, 102), (104, 103), (104, 105), (104, 106)] , proxy[3])
Makers.makeTransitAs(base, 138, [105,100, 101, 102, 103, 106], [(105, 100), (105, 101), (105, 103), (105, 106), (105, 102)] , proxy[4])
Makers.makeTransitAs(base, 139, [106,100, 101, 103, 105], [(106, 100), (106, 101), (106, 103), (106, 105)] , proxy[5])

## Tier 2 Transit ASes
Makers.makeTransitAs(base, 176, [100, 101, 102, 103, 104, 105, 106, 107], [(100, 107),(101, 107),(102, 107),(103, 107),(104, 107), (107,105), (107,106)], proxy[6])
Makers.makeTransitAs(base, 178, [101, 102, 103, 104, 105], [(101, 102),(101, 103),(101, 104),(101, 105)], proxy[7])
Makers.makeTransitAs(base, 179, [101, 102, 103, 104, 106, 108], [(108, 102), (108, 104), (108, 106), (108, 103), (108, 101)], proxy[8])
Makers.makeTransitAs(base, 180, [100, 101, 102, 103, 104, 105, 106, 109], [(109, 100), (109, 101),(109, 102),(109, 103),(109, 104),(109, 105),(109, 106)], proxy[9])
Makers.makeTransitAs(base, 181, [101, 104, 105, 106, 110], [(110, 101), (110, 104),(110, 105),(110, 106)], proxy[10])

## Tier 2 Extended for Step 8 P2P Links
Makers.makeTransitAs(base, 148, [100, 101], [(100, 101)], proxy[11])
Makers.makeTransitAs(base, 152, [100, 102], [(100, 102)], proxy[12])
Makers.makeTransitAs(base, 156, [100, 103], [(100, 103)], proxy[13])
Makers.makeTransitAs(base, 130, [100, 106], [(100, 106)], proxy[14])
Makers.makeTransitAs(base, 157, [100, 101, 102, 103, 104, 105, 106], [(103, 100),(103, 101),(103, 102),(103, 104),(103, 105),(103, 106)], proxy[15])
Makers.makeTransitAs(base, 159, [100, 101, 102, 103, 105, 106], [(103, 100),(103, 101),(103, 102),(103, 105),(103, 106)], proxy[16])
Makers.makeTransitAs(base, 151, [100, 101, 102, 103, 104, 105, 106], [(103, 100),(103, 101),(103, 104),(103, 105),(103, 106),(103,102)], proxy[17])
Makers.makeTransitAs(base, 161, [101, 103, 105, 104], [(104, 101),(104, 103),(104, 105)], proxy[18])
Makers.makeTransitAs(base, 165, [101, 102, 104, 106], [(104, 101),(104, 102),(104, 106)], proxy[19])
Makers.makeTransitAs(base, 171, [100, 101, 102, 103, 105, 106], [(106, 100),(106, 101),(106, 102),(106, 103),(106, 105)], proxy[20])
Makers.makeTransitAs(base, 172, [100, 101, 102, 103, 105, 106], [(106,100), (106, 101),(106, 103),(106, 105), (106,102)], proxy[21])
Makers.makeTransitAs(base, 173, [101, 102, 103, 105, 106], [(106, 101),(106, 103),(106, 105), (106,102)], proxy[22])
Makers.makeTransitAs(base, 166, [101, 102, 103, 105, 106], [(105, 101),(105, 102),(105, 103),(105, 106)], proxy[23])



###############################################################################
# Create single-homed stub ASes. "None" means create a host only 

#Clique-stubs
Makers.makeStubAs(emu, base, 140,  100, [None], proxy[24])
Makers.makeStubAs(emu, base, 142, 100, [None], proxy[25])
Makers.makeStubAs(emu, base, 144,  100, [None], proxy[26])
Makers.makeStubAs(emu, base, 141,  100, [None], proxy[27])
Makers.makeStubAs(emu, base, 143,  100, [None], proxy[28])
Makers.makeStubAs(emu, base, 145,  100, [None], proxy[29])

#T1-134 "Stubs", E.g. Just 1 layer deep ASNs at T1
Makers.makeStubAs(emu, base, 146,  101, [None], proxy[30])
Makers.makeStubAs(emu, base, 147,  101, [None], proxy[31])
#Makers.makeStubAs(emu, base, 148,   101, [None]) # Turned to Transit
Makers.makeStubAs(emu, base, 149,  101, [None], proxy[32])
Makers.makeStubAs(emu, base, 150,  101, [None], proxy[33])

#T1 - 135 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 151,  102, [None])
#Makers.makeStubAs(emu, base, 152,  102, [None])
Makers.makeStubAs(emu, base, 153,  102, [None], proxy[34])
Makers.makeStubAs(emu, base, 154,  102, [None], proxy[35])
Makers.makeStubAs(emu, base, 155,  102, [None], proxy[36])

#T1 - 136 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 156,  103, [None])
#Makers.makeStubAs(emu, base, 157,  103, [None])
Makers.makeStubAs(emu, base, 158,  103, [None], proxy[37])
#Makers.makeStubAs(emu, base, 159,   103, [None])
#Makers.makeStubAs(emu, base, 151,  103, [None])

#T1 - 137 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 161,   104, [None])
Makers.makeStubAs(emu, base, 162,   104, [None], proxy[38])
Makers.makeStubAs(emu, base, 163,  104, [None], proxy[39])
Makers.makeStubAs(emu, base, 164,   104, [None], proxy[40])
#Makers.makeStubAs(emu, base, 165,   104, [None])

#T1 - 138 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 166,  105, [None])
Makers.makeStubAs(emu, base, 167,  105, [None], proxy[41])
Makers.makeStubAs(emu, base, 168,  105, [None], proxy[42])
Makers.makeStubAs(emu, base, 169,  105, [None], proxy[43])
Makers.makeStubAs(emu, base, 170,  105, [None], proxy[44])

#T1 - 139 "Stubs", E.g. Just 1 layer deep ASNs at T1
#Makers.makeStubAs(emu, base, 171,  106, [None])
#Makers.makeStubAs(emu, base, 172,  106, [None])
#Makers.makeStubAs(emu, base, 173,  106, [None])
Makers.makeStubAs(emu, base, 177,  106, [None], proxy[45])
Makers.makeStubAs(emu, base, 175,  106, [None], proxy[46])

#T2 - 176 "Stubs"

#T2 - 178 "Stubs"

#T2 - 179 "Stubs"

#T2 - 180 "Stubs"

#T2 - 181 "Stubs" 


###############################################################################

# To buy transit services from another autonomous system, 
# we will use private peering  

#Clique Peering @ IX100
ebgp.addPrivatePeerings(100, [131],  [132, 128, 129, 133, 130], PeerRelationship.Peer)
#ebgp.addPrivatePeerings(100, [1239], [132, 128, 129, 133, 130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [132], [128, 129, 133, 130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [127], [128, 129, 133], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [128], [129, 133, 130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [129], [133, 130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(100, [133], [130], PeerRelationship.Peer)

#Clique-Stubs @ IX100 ## may need to use the private peerings method if ab doesnt work.
ebgp.addPrivatePeering (100, 133, 140,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 129, 141,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 130, 142, abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 128, 143,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 132, 144,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (100, 131,  145,  abRelationship = PeerRelationship.Provider)

#Clique->T1 @ IX100
ebgp.addPrivatePeerings(100, [131, 133, 132, 128, 127, 130], [134], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [131, 133, 132, 128, 127, 130, 129], [135], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [131, 132, 128, 127, 130], [136], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [131, 132, 129], [137], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [131, 133, 132], [138], PeerRelationship.Provider)
ebgp.addPrivatePeerings(100, [131, 133, 129], [139], PeerRelationship.Provider)

#T1->T2 @ T1 IX
ebgp.addPrivatePeerings(101, [134], [148, 149, 150, 146,147], PeerRelationship.Provider)
ebgp.addPrivatePeerings(103, [136], [156, 157, 158, 159, 151], PeerRelationship.Provider)
ebgp.addPrivatePeerings(102, [135], [151, 152, 153, 154, 155], PeerRelationship.Provider)
ebgp.addPrivatePeerings(104, [137], [161, 163, 162, 164, 165], PeerRelationship.Provider)
ebgp.addPrivatePeerings(105, [138], [166, 167, 168, 169,170], PeerRelationship.Provider)
ebgp.addPrivatePeerings(106, [139], [171, 172, 173, 177, 175], PeerRelationship.Provider)

#T2-> Stubs  Note: try this method...may need to do abRelationship instead. Need to add some stubs here.
#ebgp.addPrivatePeerings(107, [176], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(108, [178], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(109, [179], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(110, [180], [], PeerRelationship.Provider)
#ebgp.addPrivatePeerings(111, [181], [], PeerRelationship.Provider)

# provider to larger customer P2C Links
ebgp.addPrivatePeering (103, 136, 134,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (103, 159, 134,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (103, 136, 135,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (101, 148, 157,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (102, 153, 152,  abRelationship = PeerRelationship.Provider)
ebgp.addPrivatePeering (105, 169, 157,  abRelationship = PeerRelationship.Provider)

# Provirder-less Peering (Transit) T2 - 176
ebgp.addPrivatePeerings(100, [176], [130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [176], [146, 147], PeerRelationship.Provider)
ebgp.addPrivatePeerings(101, [176], [150], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [176], [135, 152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [176], [136, 159, 156, 157, 151], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [176], [137], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [176], [166], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [176], [139], PeerRelationship.Peer)

# Provirder-less Peering (Transit) T2 - 179
ebgp.addPrivatePeerings(101, [179], [149], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [179], [135], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [179], [157, 151], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [179], [137], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [179], [171, 173, 175], PeerRelationship.Peer)


# Provirder-less Peering (Transit) T2 - 180
ebgp.addPrivatePeerings(100, [180], [130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [180], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [180], [152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [180], [156, 158, 151], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [180], [165], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [180], [170], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [180], [139], PeerRelationship.Peer)


# Provirder-less Peering (Transit) T2 - 181
ebgp.addPrivatePeerings(101, [181], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [181], [137], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [181], [166], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [181], [171, 173], PeerRelationship.Peer)


# Provider-less Peering (Transit) T2 - 178
ebgp.addPrivatePeerings(101, [178], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [178], [135], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [178], [136], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [178], [137], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [178], [166], PeerRelationship.Peer)


# Additional P2P Links

ebgp.addPrivatePeerings(103, [134], [156,158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [134], [152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [134], [170, 167, 168, 169], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [134], [173], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [137], [134, 149], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [137], [135, 152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [137], [151, 158, 156, 157,136], PeerRelationship.Peer)

ebgp.addPrivatePeerings(105, [137], [170,166, 167, 138, 168], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [137], [172, 175, 139, 173, 171, 177], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [136], [133], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [136], [149], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [136], [138, 168, 167], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [136], [175, 139, 173], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [139], [130, 128], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [139], [148, 149, 134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [139], [158,156], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [139], [138, 168, 170, 167], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [135], [149, 134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [135], [156, 158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [135], [161], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [135], [138, 168, 167, 170], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [135], [171, 177, 175, 139, 172], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [138], [134, 149], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [138], [152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [138], [156, 158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [138], [175, 173], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [157], [130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [157], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [157], [135], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [157], [161], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [157], [168, 138, 166], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [157], [172, 139, 173, 171], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [159], [130], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [159], [148, 149], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [159], [152, 135, 151], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [159], [158, 157], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [159], [167, 170, 168, 138, 166], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [159], [139, 172, 171, 173, 175], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [151], [129], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [151], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [151], [161], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [151], [168, 138], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [151], [173, 139], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [161], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [161], [156, 158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(104, [161], [163], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [161], [170], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [165], [134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [165], [135], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [165], [172, 139], PeerRelationship.Peer)

ebgp.addPrivatePeerings(102, [155], [153], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [171], [129], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [171], [134, 149, 148], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [171], [152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [171], [151, 156, 136, 158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [171], [168, 138], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [171], [173, 175, 172], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [172], [130, 133], PeerRelationship.Peer)
ebgp.addPrivatePeerings(101, [172], [134, 149, 148], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [172], [152], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [172], [151, 156, 136, 158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [172], [138, 168, 167], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [172], [175, 173, 177], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [173], [149], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [173], [158, 156], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [173], [168, 170], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [173], [175], PeerRelationship.Peer)

ebgp.addPrivatePeerings(101, [166], [150, 134], PeerRelationship.Peer)
ebgp.addPrivatePeerings(102, [166], [152, 135], PeerRelationship.Peer)
ebgp.addPrivatePeerings(103, [166], [156, 151, 136, 158], PeerRelationship.Peer)
ebgp.addPrivatePeerings(105, [166], [170, 167], PeerRelationship.Peer)
ebgp.addPrivatePeerings(106, [166], [173, 171, 175, 139, 172], PeerRelationship.Peer)

ebgp.addPrivatePeerings(105, [168], [170, 167], PeerRelationship.Peer)

ebgp.addPrivatePeerings(105, [169], [167], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [156], [129, 128], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [152], [133], PeerRelationship.Peer)

ebgp.addPrivatePeerings(100, [148], [128], PeerRelationship.Peer)


# Additional P2P Links
#ebgp.addPrivatePeerings(102, [102], [172, 152, 155, 153, 165, 135], PeerRelationship.Peer)
#ebgp.addRsPeers(100, [128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 151, 152, 156, 171, 176, 180])
#ebgp.addRsPeers(101, [134, 135, 136, 137, 139, 146, 147, 148, 149, 150, 151,157, 159, 161, 166, 172, 173, 176, 178, 179, 180, 181])
#ebgp.addRsPeers(102, [135, 137, 138, 151, 152, 153, 154,155, 157, 159, 165, 166, 171, 172, 176, 179, 180])
#ebgp.addRsPeers(103, [134, 136, 137, 138, 139, 151, 156, 157, 158, 159, 161, 172, 176, 178, 179, 180])
#ebgp.addRsPeers(104, [135, 137, 161, 162, 163, 164, 165, 176, 178, 179, 180])
#ebgp.addRsPeers(105, [134, 135, 137, 138, 151, 157, 166, 167, 168, 169, 170, 171, 172, 173, 176, 178, 180])
#ebgp.addRsPeers(106, [130, 134,135,136,137,138,151,157,159,165,166,171,172,173,175,176,177,179,180,181])
#ebgp.addRsPeers(107, [176])
#ebgp.addRsPeers(108, [179])
#ebgp.addRsPeers(109, [180])
#ebgp.addRsPeers(110, [181])
#ebgp.addRsPeers(111, [])




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
emu.compile(Docker(), './output', override=True)

