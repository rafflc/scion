# EPIC extension

This document presents the design for the EPIC extension

* Author: Christopher Raffl
* Last updated: 2019-05-06
* Status: draft

## Overview

EPIC (Every Packet Is Checked in a Path-Aware internet), implemented as a SCION hop-by-hop extension, proposes a series of data-plane protocols that provide different levels of authentication and path validation properties for end points and intermediate routers.\
The 4 levels allow for the following:
1. Improved Path Authorization
2. Source Authentication
3. End-Point Path Validation
4. Full Path Validation

## Notation

    (^)         xor
    |           bitstring concatenation

    _           subscript
    ^           superscript
    $...$       LaTeX math-mode
    \...        LaTeX symbol

    x'          indicates that variable/field x refers to path H_D -> H_S
                (only relevant for source validation packets)

    K_i^S       K_{A_i -> A_0:H_S} = symmetric key between host H_S in AS A_0 and AS A_i
    K_{SD}      K_{A_l:H_D -> A_0:H_S} = symmetric key between host H_S in AS
                A_0 and host H_D in AS A_l

    H(x)        Hash function of value x
    MAC_K(x)    Message authentication code using key K of value x
    Ceil(x)     Least integer value greater than or equal to x
    x[a:b]      Substring from byte a (inclusive) to byte b (exclusive) of x

## Definitions

    $\sigma$ =  hop authenticator (equals not truncated MAC of HF)
                MAC_K(TS|Flags_HF|ExpTime|InIF/PeerIF|EgIF|HF')
                where:
                K = local symmetric key, only known to local AS
                TS = PCB's info field timestamp
                Flags_HF = flags field of HF only with immutable flags set
                ExpTime = offset relative to PCB's info field TS
                InIF/PeerIF = ingress interface (in direction of beaconing/of peering link)
                EgIF = egress interface
                HF' = hop field of previous AS (in beaconing direction) with only immutable flags set

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
    |                            PathHash                           |    1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    Standard extension header:
    NextHdr =   indicates type of next extension (if any)
    HdrLen =    depends on level and flags
    ExtType =   0x03

ExtType: So far, hop-by-hop (HBH) extensions up to 0x02 are already implemented. According to section 15.1.4 of the SCION book, 0x03 is reserved for One-Hop Path extension, which is however not implemented.

    Flags:
    r           unused
    s           source validation packet flag
    L           level

    TS          timestamp offset: current_time - TS_{bc} (timestamp of first info field)
    PathHash    H(Path)[0:4]
    PldHash     H(Pld)[0:4]


#### Level 1

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |       l       |       i       |              V_1              |    2
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            V_{l-1}            |              V_l              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    NOTE: if (1 + l) % 4 != 0, padding required

    HdrLen      2 + Ceil((1 + l)/4)

    Flags:
    s           0b0
    L           0b00

    l           number of total hops
    i           number of current hop

    V_i         Hop validation field for hop i
                H(TS|PathHash|PldHash|$\sigma_i$)[0:2]

#### Level 2

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}...                         +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}                            +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |       l       |       i       |              V_1              |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            V_{l-1}            |              V_l              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    NOTE: if (1 + l) % 4 != 0, padding required

    HdrLen      4 + Ceil((1 + l)/4)

    Flags:
    s           0b0
    L           0b01

    V_{SD}      Destination validation field
                MAC_{K_{SD}}(TS|H(Path)|H(Pld))[0:16]
    l           number of total hops
    i           number of current hop
    V_i         Hop validation field for hop i
                MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:2]


#### Level 3

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}...                         +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}                            +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |       l       |       i       |              V_1              |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           V_{l-1,j}           |            V_{l,j}            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    NOTE: if (1 + l) % 4 != 0, padding required

    HdrLen =    4 + Ceil((1 + l)/4)

    Flags:
    s           0b0
    L           0b10

    V_{SD}      Destination validation field
                MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]
    l           number of total hops
    i           number of current hop
    V_{i,j}     Hop validation field for hop i after processing by AS_j (updated at hop j = i)
                for i >  j: C_i^1
                for i <= j: C_i^2
    C_i^a       MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[2*(a-1):2*a]

#### Level 4


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}...                         +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}                            +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |       l       |       i       |              V_1              |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           V_{l-1,j}           |            V_{l,j}            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    NOTE: if (1 + l) % 4 != 0, padding required

    HdrLen      4 + Ceil((1 + l)/4)

    Flags:
    s           0b0
    L           0b11

    V_{SD}      Destination validation field
                MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]
    l           number of total hops
    i           number of current hop
    V_{i,j}     Hop validation field for hop i after processing by AS_j
                for i >  j: C_i^1 (^) C_{i-k}^3 {k = 2^z | 0<=z; k<=i-j}
                for i <= j: C_i^2
    C_i^a       MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[2*(a-1):2*a]

#### Source validation packet

Note: This type of packet is always sent from some Host H_D to another host H_S in order to validate an earlier packet from H_S to H_D.\
In this description here, fields referring to the packet H_D -> H_S are marked with a ' at the end, while fields referring to the (original) packet H_S -> H_D are not.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |    NextHdr'   |     HdrLen'   |    ExtType'   |r|r|r|r|r|s'|L'|    0
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              TS'                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash'                          |    1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash'                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    2
    +                             V_{SD}'...                        +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                                                               |    3
    +                          ...V_{SD}'                           +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                            PathHash                           |    4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              TS                               |    5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       l'      |       i'      |              V_1'             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    6
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              V_l'             |             V_{1,l}           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |                              ...                              |    HdrLen - 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           V_{l-1,l}           |             V_{l,l}           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

    NOTE: if (3 + l' + l) % 4 != 0, padding required

    NextHdr'       indicates type of next extension (if any)
    HdrLen'        5 + Ceil((3 + l' + l)/4)
    ExtType'       0x03

    Flags:
    s'             0b1
    L'             0b00

    TS'            current_time' - TS_{bc}' (timestamp of first info field)
    PathHash'      H(Path')[0:4]
    PldHash'       H(Pld')[0:4]
    V_{SD}'        Source validation field
                   MAC_{K_{SD}}(TS'|H(Path')|H(Pld')|V_{1,l}|...|V_{l,l})[0:16]
    PathHash       H(Path)[0:4]
    PldHash        H(Pld)[0:4]
    TS             current_time - TS_{bc} (timestamp of first info field)
    l'             number of total hops of path H_D -> H_S
    i'             number of current hop of path H_D -> H_S
    V_i'           Hop validation field for hop i'
                   H(TS'|PathHash'|PldHash'|$\sigma_i$')[0:2]
    V_{i,l}        Hop validation field for hop i at end of path H_S -> H_D
                   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[2:4]

#### How to get l

The number l can be obtained by counting all hop fields in the standard SCION path except those with a VRFY-ONLY flag set.\
Note that it is not possible to directly use the SegLen fields of the info fields as hop fields can use more than 8 Bytes (continue flag).\
**TODO:** How do we process HFs with continue flag?


### Procedure at source (H_S)

The source initializes all fields of the packet

#### Level 1

Requirements:
* $\sigma_i$ for all i=1...l

Procedure:

    Get needed information ($\sigma$)
    Write and calculate all fields (described below)
    Send packet

Definition of fields and variables:

    NextHdr     type of next extension (already handled)
    HdrLen      2 + Ceil(l/4)
    ExtType     0x03
    s           0b0
    L           0b00
    TS          current_time - TS_{bc} of first infofield of path
                TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)
                TODO: Concrete formula of calculating TS

    PathHash    H(Path)[0:4]
                Path = Forwarding Path in SCION header (p. 342)

    PldHash     H(Pld)[0:4]
                Pld = Layer-4 protocol and data (p. 342)

    l           number of hops (see above how to derive)
    i           1

    for all i=1...l:
        V_i =       H(TS|PathHash|PldHash|$\sigma_i$)[0:2]



#### Level 2

Requirements:
* $\sigma_i$ for all i=1...l
* K_{SD}
* for all i=1...l: K_i^s

Procedure:

    Get needed information ($\sigma$, keys)
    Write and calculate all fields (described below)
    Send packet

Definition of fields and variables:

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

    l =         number of hops (see above how to derive)
    i =         1

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

    l =         number of hops (see above how to derive)
    i =         1

    for all i=1...l:
        C_i =   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:4]
        V_{i,0} = C_i[0:2]
        V_{i,l} = C_i[2:4]

    V_{SD} =    MAC_{K_{SD}}(TS|PathHash|PldHash|V_{1,l}|...|V_{l,l})[0:16]

for the next step we need some kind of dict. (Also we need to store l, otherwise there is no efficient way to derive it):

    store V_{1,l},...,V_{l,l} in (dict(TS|PathHash|PldHash), l)

when receiving source validation packet(NOTE: fields referring to packet H_D -> H_S are marked with a ' at the end, while fields referring to packet H_S -> H_D are not):


    if PathHash' != H(Path')[0:4] || PldHash' != H(Pld)[0:4]:
        validation failed
    if(current time' - TS_{bc}' - TS') \notin acceptable lifetime:
        validation failed
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    values <- dict(TS|PathHash|PldHash)
        if this fails -> validation failed
    if V_{SD}'
        != MAC_{K_{SD}}(TS'|PathHash'|PldHash'|V_{1,l}|...|V_{l,l})[0:16]:
        validation failed
    for all i=1...l:
        if values.V_{i,l} != V_{i,l}:
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

    l =         number of hops (see above how to derive)
    i =         1

    for all i=1...l:
        C_i =   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:6]
        V_{i,0} = C_i[0:2]
        V_{i,l} = C_i[2:4]
        for d=1; i-d > 0; d <- 2d:
            V_{i,0} = V_{i, 0} (^) C_{i-d}[4:6]

    V_{SD} =    MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]

for the next step we need some kind of dict. (Also we need to store l, otherwise there is no efficient way to derive it):

    store V_{1,l},...,V_{l,l} in (dict(TS|PathHash|PldHash), l)

when receiving source validation packet(NOTE: fields referring to packet H_D -> H_S are marked with a ' at the end, while fields referring to packet H_S -> H_D are not):


    if PathHash' != H(Path')[0:4] || PldHash' != H(Pld)[0:4]:
        validation failed
    if(current time' - TS_{bc}' - TS') \notin acceptable lifetime:
        validation failed
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    values <- dict(TS|PathHash|PldHash)
        if this fails -> validation failed
    if V_{SD}'
        != MAC_{K_{SD}}(TS'|PathHash'|PldHash'|V_{1,l}|...|V_{l,l})[0:16]:
        validation failed
    for all i=1...l:
        if values.V_{i,l} != V_{i,l}:
            validation failed

    validation succeeded

### Procedure at intermediate routers

AS checks interfaces and the MAC of the HF (this is already done by standard SCION implementation)\
Steps performed by EPIC extension:

#### Level 1

NOTE: fields referring to packet H_D -> H_S are marked with a ' at the end, while fields referring to packet H_S -> H_D are not

    if(s = 0b0):
        if(current time - TS_{bc} - TS) \notin acceptable lifetime:
            drop packet
            // **TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

        get current i
        //i will be at a different place depending on s flag
        calculate $\sigma_i$
        if V_i != H(TS|PathHash|PldHash|$\sigma_i$)[0:2]:
            drop packet
        forward packet

    else:
        if(current time' - TS_{bc}' - TS') \notin acceptable lifetime:
            drop packet
for TS_{bc}' we always have to refer to first INF. For how exactly the time is derived see 15.6 on p. 349

        get current i
        //i will be at a different place depending on s flag
        calculate $\sigma_i$
        if V_i' != H(TS'|PathHash'|PldHash'|$\sigma_i$)[0:2]:
            drop packet
        forward packet


#### Level 2

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    get current i
    calculate $\sigma_i$
    calculate K_i^S
    if V_i != MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:2]:
        drop packet
    forward packet



#### Level 3

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    get current i
    calculate $\sigma_i$
    calculate K_i^S
    C = MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:4]
    if V_i != C[0:2]:
        drop packet
    replace V_i in packet with C[2:4]
    forward packet

#### Level 4

    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    get current i
    get l
    calculate $\sigma_i$
    calculate K_i^S
    C = MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:6]
    if V_i != C[0:2]:
        drop packet
    replace V_i in packet with C[2:4]
    for d = 1; i + d <= l; d = 2*d:
        V_{i+d} = V_{i+d} (^) C[4:6]
    forward packet

### Procedure at destination H_D

From Level 2, the destination needs to obtain the DRKey shared with the source from the certificate server of its AS.\
From Level 3, the destination additionally needs hop authenticators for a path to the source.

#### Level 1

Requirements:
* none

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    process payload

#### Level 2

Requirements:
* K_{SD}

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    if V_{SD} != MAC_{K_{SD}}(TS|H(Path)|H(Pld))[0:16]:
        drop packet

    process payload


#### Level 3

Requirements:
* K_{SD}
* $\sigma_i$ for all i=1...l' for path H_D -> H_S

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    if V_{SD} != MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]:
        drop packet

create new Level 1 source validation packet:\
Payload of this packet could be used for other stuff, e.g., ACKs of the transport protocol.

Definition of fields and variables (NOTE: fields referring to packet H_D -> H_S are marked with a ' at the end, while fields referring to packet H_S -> H_D are not):

    NextHdr' =     type of next extension (already handled)
    HdrLen' =      5 + Ceil((2 + l' + l)/4)
    ExtType' =     0x03

ExtType: Implemented are HBH extensions up to 0x02, but maybe 0x03 is still already occupied

    Flags:
    s'=            0b1
    L'=            0b00

    TS' =          current_time' - TS_{bc}' of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash'=     H(Path')[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash'=      H(Pld')[0:4]
Pld = Layer-4 protocol and data (p. 342)

    V_{SD}'=       Source validation field
                MAC_{K_{SD}}(TS'|H(Path')|H(Pld')|V_{1,l}|...|V_{l,l})[0:16]
    PathHash =     H(Path)[0:4]
    PldHash =      H(Pld)[0:4]
    TS =           TS
    for all i=1...l':
        V_i' =      H(TS'|PathHash'|PldHash'|$\sigma_i$')[0:2]

    for all i=1...l:
        V_{i,l} =  V_{i,l}

    send Level 1 source validation packet

then

    process old payload

#### Level 4

Requirements:
* K_{SD}
* $\sigma_i$ for all i=1...l' for path H_D -> H_S
*

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time - TS_{bc} - TS) \notin acceptable lifetime:
        drop packet
**TODO:** Define precisely how TS is calculated. Note that we have 4 Bytes instead of 1 Byte for ExpTime of hop fields.

    if V_{SD} != MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]:
        drop packet

create new Level 1 source validation packet:\
Payload of this packet could be used for other stuff...

Definition of fields and variables (NOTE: fields referring to packet H_D -> H_S are marked with a ' at the end, while fields referring to packet H_S -> H_D are not):

    NextHdr' =     type of next extension (already handled)
    HdrLen' =      5 + Ceil((2 + l' + l)/4)
    ExtType' =     0x03

ExtType: Implemented are HBH extensions up to 0x02, but maybe 0x03 is still already occupied

    Flags:
    s'=            0b1
    L'=            0b00

    TS' =          current_time' - TS_{bc}' of first infofield of path
TS_{bc} info: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348)

    PathHash'=     H(Path')[0:4]
Path = Forwarding Path in SCION header (p. 342)

    PldHash'=      H(Pld')[0:4]
Pld = Layer-4 protocol and data (p. 342)

    V_{SD}'=       Source validation field
                MAC_{K_{SD}}(TS'|H(Path')|H(Pld')|V_{1,l}|...|V_{l,l})[0:16]
    PathHash =     H(Path)[0:4]
    PldHash =      H(Pld)[0:4]
    TS =           TS
    for all i=1...l':
        V_i' =      H(TS'|PathHash'|PldHash'|$\sigma_i$')[0:2]

    for all i=1...l:
        V_{i,l} =  V_{i,l}

    send Level 1 source validation packet

then

    process old payload




## Implementation
