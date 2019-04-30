# EPIC extension

This document presents the design for the EPIC extension

* Author: Christopher Raffl
* Last updated: 2019-04-30
* Status: draft

## Overview

EPIC (Every Packet Is Checked in a Path-Aware internet), implemented as a SCION hop-by-hop extension, proposes a series of data-plane protocols that provide different levels of authentication and path validation properties for end points and intermediate routers.\
The 4 levels allow for the following:
1. Improved Path Authorization
2. Authentication
3. End-Point Path Validation
4. Full Path Validation

## Notation

    ^ =         xor
    | =         bitstring concatenation

    C_i = _     stands for subscript
    C^i = ^     stands for superscript
    $...$ =     corresponds to LaTeX math-mode
    \...  =     LaTeX symbol

    K_i^S  =    K_{A_i -> A_0:H_S} = symmetric key between host H_S in AS A_0 and AS A_i
    K_{SD} =    K_{A_l:H_D -> A_0:H_S} = symmetric key between host H_S in AS A_0 and  host H_D in 
                AS A_l

    H(x) =      Hash function of value x
    MAC_K(x) =  Message authentication code using key K of value x
    Ceil(x) =   Least integer value greater or equal to x
    x[a:b] =    Substring from byte a (inclusive) to byte b (exclusive) of x

    

## Design

### Packet design

#### Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |    NextHdr    |     HdrLen    |    ExtType    |r|r|r|r|r|s| L |    0
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              TS                               |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    Standard extension header:
    NextHdr =   indicates type of next extension (if any)
    HdrLen =    depends on level and flags
    ExtType =   0x03

    Flags:
    r =         unused
    s =         source validation packet flag
    L =         level

    TS =        timestamp offset: current_time - TS_{bc} 


#### Level 1

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash                           |    1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |              V_1              |              V_2              |    2
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
    |                              ...                              |   
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            V_{l-1}            |              V_l              |       
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    HdrLen =    2 + Ceil(l/4)
    
    Flags:
    s =         0b0
    L =         0b00

    PathHash =  H(Path)[0:4]
    PldHash =   H(Pld)[0:4]
    V_i =       Hop validation field for hop i
                H(TS|H(Path)|H(Pld)|$\sigma_i$)[0:2]

#### Level 2

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash                           |    1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}...                         +
    |                                                               | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}                            +
    |                                                               | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |              V_1              |              V_2              |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
    |                              ...                              |   
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            V_{l-1}            |              V_l              |       
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    HdrLen =    4 + Ceil(l/4)

    Flags:
    s =         0b0
    L =         0b01

    PathHash =  H(Path)[0:4]
    PldHash =   H(Pld)[0:4]
    V_{SD} =    Destination validation field
                MAC_{K_{SD}}(TS|H(Path)|H(Pld))[0:16]
    V_i =       Hop validation field for hop i
                MAC_{K_i^s}(TS|H(Path)|H(Pld)|$\sigma_i$)[0:2]
    

#### Level 3

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash                           |    1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}...                         +
    |                                                               | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}                            +
    |                                                               |     
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |            V_{1,j}            |            V_{2,j}            |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           V_{l-1,j}           |            V_{l,j}            |       
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    HdrLen =    4 + Ceil(l/4)

    Flags:
    s =         0b0
    L =         0b10

    PathHash =  H(Path)[0:4]
    PldHash =   H(Pld)[0:4]
    V_{SD} =    Destination validation field
                MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]
    V_{i,j} =   Hop validation field for hop i, updated at hop j = i
                for i >  j: C_i^1
                for i <= j: C_i^2
    C_i^a =     MAC_{K_i^s}(TS|H(Path)|H(Pld)|$\sigma_i$)[2*(a-1):2*a]

#### Level 4


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash                           |    1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}...                         +
    |                                                               | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}                            +
    |                                                               |     
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |            V_{1,j}            |            V_{2,j}            |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           V_{l-1,j}           |            V_{l,j}            |       
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    HdrLen =    4 + Ceil(l/4)

    Flags:
    s =         0b0
    L =         0b11

    PathHash =  H(Path)[0:4]
    PldHash =   H(Pld)[0:4]
    V_{SD} =    Destination validation field
                MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]
    V_{i,j} =   Hop validation field for hop i, updated at hop j = i
                for i >  j: C_i^1 ^ C_{i-k}^3 {k = 2^z | 0<=z; k<=i-j}
                for i <= j: C_i^2
    C_i^a =     MAC_{K_i^s}(TS|H(Path)|H(Pld)|$\sigma_i$)[2*(a-1):2*a]

#### Source validation packet

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash                           |    1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}^(s)...                     +
    |                                                               | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}^(s)                        +
    |                                                               | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash^(s)                       |    4  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash^(s)                        |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              TS^(s)                           |    5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              V_1              |              V_2              |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+----- 
    |                              ...                              |    6
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              V_l              |        V_{1,l^(s)}^(s)        |    
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       V_{l-1,l^(s)}^(s)       |        V_{l,l^(s)}^(s)        | 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    HdrLen =          5 + Ceil((2 + l + l^(s))/4)

    Flags:
    s =               0b1
    L =               0b00

    PathHash =        H(Path)[0:4]
    PldHash =         H(Pld)[0:4]
    V_{SD}^(s)=       Source validation field
                
            MAC_{K_{SD}}(TS^(s)|PathHash^(s)|PldHash^(s)|V_{1,l^(s)}^(s)|...|V_{l,l^(s)}^(s))[0:16]
    PathHash^(s) =    H(Path^(s))[0:4]
    PldHash^(s) =     H(Pld^(s))[0:4]
    TS^(s) =          timestamp offset for sent packet: current_time^(s) - TS_{bc}^(s)
    V_i =             Hop validation field for hop i
                      H(TS|H(Path)|H(Pld)|$\sigma_i$)[0:2]  
    V_{i,l^(s)}^(s) = Hop validation field for hop i of sent packet at end of its path
                      MAC_{K_i^s}(TS^(s)|H(Path^(s))|H(Pld^(s))|$\sigma_i$^(s))[2:4]

#### How to get l

Consider path field of packet. Start at first info field and check if UP-flag is set. If yes (no), count all following hop fields with non-nill EgIF (non-nill InIF) and no VRFY-ONLY flag set until next info field reached. At second info field (if any), proceed in the same way for the UP-flag and check furthermore, if SHORTCUT-flag is set. If yes, do also not count following info fields with XOVER-flag set. At third info field (if any), again check the UP-flag.\
The obtained number l should correspond to the number of ASes the path traverses minus the AS in which the source host is situated.

#### How to get i

In order to get i, proceed in the exact same way as described to obtain l. At each hop field (also for the ones not counted) check if they are the same as CurrHF. If yes, the number of relevant hop fields counted so far corresponds to i.

### Procedure at source (H_S)

The source initializes all fields of the packet

#### Level 1

Requirements:
* $\sigma_i$ for all i=1...l

Procedure:

    Get needed information ($\sigma$)
    Calculate information for fields of packet (l)
    Write and calculate all fields (described below)
    Send packet

Definition of fields and variables:

    l =         number of hops

    NextHdr =   type of next extension (already handled)
    HdrLen =    2 + Ceil(l/4)
    ExtType =   0x03
    s =         0b0
    L =         0b00
    TS =        current_time - TS_{bc} of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash =  H(Path)[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
Pld = Layer-4 protocol and data (p. 342)

    for all i=1...l:
    V_i =       H(TS|PathHash|PldHash|$\sigma_i$)[0:2]



#### Level 2

Requirements:
* $\sigma_i$ for all i=1...l
* K_{SD}
* for all i=1...l: K_i^s

Procedure:

    Get needed information ($\sigma$, keys)
    Calculate information for fields of packet (l)
    Write and calculate all fields (described below)
    Send packet

Definition of fields and variables:

    l =         number of hops

    NextHdr =   type of next extension (already handled)
    HdrLen =    4 + Ceil(l/4)
    ExtType =   0x03
    s =         0b0
    L =         0b01
    TS =        current_time - TS_{bc} of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash =  H(Path)[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
Pld = Layer-4 protocol and data (p. 342)

    V_{SD} =    MAC_{K_{SD}}(TS|PathHash|PldHash)[0:16]

    for all i=1...l:
    V_i =       MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:2]

#### Level 3

Requirements:
* $\sigma_i$ for all i=1...l
* K_{SD}
* for all i=1...l: K_i^s 

Procedure:\
**TODO:** How to do step 4

    Get needed information ($\sigma$, keys)
    Calculate information for fields of packet (l)
    Write and calculate all fields (described below)
    Store packet information with key (TS|PathHash|PldHash) 
    Send packet

    When answer received:
    Validate packet(described below)

Definition of fields and variables:

    l =         number of hops

    NextHdr =   type of next extension (already handled)
    HdrLen =    4 + Ceil(l/4)
    ExtType =   0x03
    s =         0b0
    L =         0b10
    TS =        current_time - TS_{bc} of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash =  H(Path)[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
Pld = Layer-4 protocol and data (p. 342)

    for all i=1...l:
        C_i =   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:4]
        V_{i,0} = C_i[0:2]
        V_{i,l} = C_i[2:4]

    V_{SD} =    MAC_{K_{SD}}(TS|PathHash|PldHash|V_{1,l}|...|V_{l,l})[0:16]

for the next step we need some kind of dict. (Also we need to store l, otherwise there is no efficient way to derive it):

    store V_{1,l},...,V_{l,l} in (dict(TS|PathHash|PldHash), l)

when receiving source validation packet:

    if PathHash != H(Path) || PldHash != H(Pld):
        validation failed
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        validation failed
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    get values val = dict(TS^(s)|PathHash^(s)|PldHash^(s))
        if this fails -> validation failed
    if V_{SD}^(s) 
        != MAC_{K_{SD}}(TS^(s)|PathHash^(s)|PldHash^(s)|V_{1,l^(s)}^(s)|...|V_{l,l^(s)}^(s))[0:16]:
        validation failed
    for all i=1...l^(s):
        if val.V_{i,l} != V_{i,l^(s)}^(s):
            validation failed

    validation succeeded

#### Level 4

Requirements:
* $\sigma_i$ for all i=1...l
* K_{SD}
* for all i=1...l: K_i^s 

Procedure:\
**TODO:** How to do step 4

    Get needed information ($\sigma$, keys)
    Calculate information for fields of packet (l)
    Write and calculate all fields (described below)
    Store packet information with key (TS|PathHash|PldHash) 
    Send packet

    When answer received:
    Validate packet(described below)

Definition of fields and variables:

    l =         number of hops

    NextHdr =   type of next extension (already handled)
    HdrLen =    4 + Ceil(l/4)
    ExtType =   0x03
    s =         0b0
    L =         0b11
    TS =        current_time - TS_{bc} of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash =  H(Path)[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
Pld = Layer-4 protocol and data (p. 342)

    for all i=1...l:
        C_i =   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:6]
        V_{i,0} = C_i[0:2]
        V_{i,l} = C_i[2:4]
        for d=1; i-d > 0; d <- 2d:
            V_{i,0} = V_{i, 0} ^ C_{i-d}[4:6]

    V_{SD} =    MAC_{K_{SD}}(TS|PathHash|PldHash|V_{1,l}|...|V_{l,l})[0:16]

for the next step we need some kind of dict. (Also we need to store l, otherwise there is no efficient way to derive it):

    store V_{1,l},...,V_{l,l} in (dict(TS|PathHash|PldHash), l)

when receiving source validation packet:

    if PathHash != H(Path) || PldHash != H(Pld):
        validation failed
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        validation failed
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    get values val = dict(TS^(s)|PathHash^(s)|PldHash^(s))
        if this fails -> validation failed
    if V_{SD}^(s) 
        != MAC_{K_{SD}}(TS^(s)|PathHash^(s)|PldHash^(s)|V_{1,l^(s)}^(s)|...|V_{l,l^(s)}^(s))[0:16]:
        validation failed
    for all i=1...l^(s):
        if val.V_{i,l} != V_{i,l^(s)}^(s):
            validation failed

    validation succeeded

### Procedure at intermediate routers

AS checks interfaces, timestamp and the MAC of the HF (this is already done by standard SCION implementation)\
Steps performed by EPIC extension:
(does it really make sense to check PldHash = H(Pld) && PathHash = H(Path) at every router? Consequence: Either use PldHash and PathHash to check V_i or calculated values. Here I will ommit this. Reason: It does not really improve anything but slows the processing down enormously)

#### Level 1

Requirements:
* none
*

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    get current i
    calculate $\sigma_i$
    //V_i will be at a different place depending on s flag
    if V_i != H(TS|PathHash|PldHash|$\sigma_i$)[0:2]:
        drop packet    
    forward packet

#### Level 2

Requirements:
* K_i^S
*

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    get current i
    calculate $\sigma_i$
    if V_i != MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:2]:
        drop packet    
    forward packet



#### Level 3

Requirements:
* K_i^S
*

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    get current i
    calculate $\sigma_i$
    C = MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:4]
    if V_i != C[0:2]:
        drop packet 
    replace V_i in packet with C[2:4]  
    forward packet

#### Level 4

Requirements:
* K_i^S
*

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    get current i
    get l
    calculate $\sigma_i$
    C = MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:6]
    if V_i != C[0:2]:
        drop packet 
    replace V_i in packet with C[2:4]  
    for d = 1; i + d <= l; d = 2*d:
        V_{i+d} = V_{i+d} ^ C[4:6]
    forward packet

### Procedure at destination H_D

#### Level 1

Requirements:
* none
*

    if PathHash != H(Path) || PldHash != H(Pld):
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

    process payload

#### Level 2

Requirements:
* K_{SD}
*

    if PathHash != H(Path) || PldHash != H(Pld):
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349
    
    if V_{SD} != MAC_{K_{SD}}(TS|PathHash|PldHash)[0:16]:
        drop packet

    process payload


#### Level 3

Requirements:
* K_{SD}
* $\sigma_i$ for all i=1...l for path H_D -> H_S
*

    if PathHash != H(Path) || PldHash != H(Pld):
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349
    
    if V_{SD} != MAC_{K_{SD}}(TS|PathHash|PldHash|V_{1,l}|...|V_{l,l})[0:16]:
        drop packet

create new Level 1 source validation packet:\
Payload of this packet could be used for other stuff.

Definition of fields and variables:

    everything with ^(s) is the old path; everything without is new

    l =         number of hops of path H_D -> H_S
    l^(s) =     number of hops of path H_S -> H_D

    NextHdr =   type of next extension (already handled)
    HdrLen =    5 + Ceil((2 + l + l^(s))/4)
    ExtType =   0x03
    s =         0b1
    L =         0b00
    TS =        current_time - TS_{bc} of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash =  H(Path)[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
Pld = Layer-4 protocol and data (p. 342)

    V_{SD}^(s)=       old V_{SD}
    PathHash^(s) =    old PathHash
    PldHash^(s) =     old PldHash
    TS^(s) =          old TS

    for all i=1...l:
        V_i =       H(TS|PathHash|PldHash|$\sigma_i$)[0:2]
$\sigma$?
    
    for all i=1...l^(s):
        V_{i,l^(s)}^(s) = old V_{i,l} 

    send Level 1 source validation packet

then

    process old payload

#### Level 4

Requirements:
* K_{SD}
* $\sigma_i$ for all i=1...l for path H_D -> H_S
*

    if PathHash != H(Path) || PldHash != H(Pld):
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
for TS_{bc} we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349
    
    if V_{SD} != MAC_{K_{SD}}(TS|PathHash|PldHash|V_{1,l}|...|V_{l,l})[0:16]:
        drop packet

create new Level 1 source validation packet:\
Payload of this packet could be used for other stuff...

Definition of fields and variables:

    everything with ^(s) is the old path; everything without is new

    l =         number of hops of path H_D -> H_S
    l^(s) =     number of hops of path H_S -> H_D

    NextHdr =   type of next extension (already handled)
    HdrLen =    5 + Ceil((2 + l + l^(s))/4)
    ExtType =   0x03
    s =         0b1
    L =         0b00
    TS =        current_time - TS_{bc} of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash =  H(Path)[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
Pld = Layer-4 protocol and data (p. 342)

    V_{SD}^(s)=       old V_{SD}
    PathHash^(s) =    old PathHash
    PldHash^(s) =     old PldHash
    TS^(s) =          old TS

    for all i=1...l:
        V_i =       H(TS|PathHash|PldHash|$\sigma_i$)[0:2]
$\sigma$?
    
    for all i=1...l^(s):
        V_{i,l^(s)}^(s) = old V_{i,l} 

    send Level 1 source validation packet

then

    process old payload


### Open questions

**$\sigma$:**\
*Edit: This is not really a good idea since the hop authenticators won't serve the same purpose anymore*\
Instead of using K_A as keys for the MAC calculation, why not use K_{i}^S. With this, there is no need of distributing the hop authenticator in advance. From Level 2-4, this key is anyway fetched from the certificate server, and AS i needs to derive it anyway on the fly. Also, there is not really a loss in security, since only AS i and the source can derive it.\
For Level 1, either we have to fetch the DRKey for K_{i}^S as well, or we could e.g. use a Hash.

My proposition thus would be to define the following (for Level 2-4):

    $\sigma$_i = MAC_{K_i^S}(TS_{INF}|HI|V')

    where:
    TS_{INF} is the time stamp of the corresponding info field,
    HI = (ExpTime|IgIF|EgIF) of the hop field,
    V' = HVF of the preceding hop (V_{i-1}).

and for Level 1:

    $\sigma$_i = H(TS_{INF}|HI|V')

    where:
    TS_{INF} is the time stamp of the corresponding info field,
    HI = (ExpTime|IgIF|EgIF) of the hop field,
    V' = HVF of the preceding hop (V_{i-1}).

## Implementation

