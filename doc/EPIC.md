# EPIC extension

This document presents the design for the EPIC extension

* Author: Christopher Raffl
* Last updated: 2019-05-08
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

    K_i^S       K_{A_i -> A_0:H_S}^{EPIC} = symmetric key between host H_S in AS A_0 and AS A_i for EPIC
    K_{SD}      K_{A_D:H_D -> A_0:H_S}^{EPIC} = symmetric key between host H_S in AS
                A_0 and host H_D in AS A_D for EPIC
    SV_A        Local and AS-specific secret value of AS A

    H(x)        Hash function of value x
    MAC_K(x)    Message authentication code using key K of value x
    PRF_K(x)    Pseudorandom function using key K and input x
    Ceil(x)     Least integer value greater than or equal to x
    Floor(x)    Biggest integer value smaller than or equal to x
    x[a:b]      Substring from byte a (inclusive) to byte b (exclusive) of x

## Definitions and Derivations

### $\sigma$ (Hop auhenticator):

    $\sigma$ =  MAC_{SV_A}(TS|Flags_HF|ExpTime|InIF/PeerIF|EgIF|HF')
                where:
                TS = PCB's info field timestamp
                Flags_HF = flags field of HF only with immutable flags set
                ExpTime = offset relative to PCB's info field TS
                InIF/PeerIF = ingress interface (in direction of beaconing/of peering link)
                EgIF = egress interface
                HF' = hop field of previous AS (in beaconing direction) with only immutable flags set

This hop authenticator equals the MAC of the HF calculated during beaconing, with the difference that here it is not truncated. All hops on route can recalculate the corresponding $\sigma$ on the fly since they can get SV_A. However, H_S has to somehow gather all $\sigma$s before it can construct the packets. A mechanism of how this could be done, is presented in the following:\
The first modification affects the beaconing. Here we leverage the already available beacon extension infrustructure. In each AS entry, the not truncated version of the MAC of the HopEntry and possible PeerEntries are stored as an extension. In the next step, when the paths are being created and distributed, we do not only have to store the paths, but also the not truncated version of the corresponding MACs. Now in the final step, when H_S queries its path server for path segment, it receives not only the paths, but also all corresponding $\sigma$s.\
*Note: Here we assume that all ASes calculate their MAC as described in the book on p. 122 and 123. However, as stated on p. 349, ASes itself can freely decide how to generate MACs and what size they should have. In the case of an AS choosing another method, the computation of $\sigma$ in that AS has to be adapted.*


### Timestamp:

    TS =        (CT - TS_inf) * Floor(2^32/(24*60*60*1'000'000))
                where:
                CT = construction time in microseconds
                TS_inf = timestamp of first infofield * 1'000'000

The timestamp encodes the construction time of the packet in a 4 byte unsigned int with granularity of ~20 microseconds. The represented time is relative and depends on the timestamp of the first InfoField of the path. Since the ExpTime of a HopField is limited to one day, the granularity was chosen such that up to one day can be represented as well.\
*(TS_inf: created by initiator of corresponding PCB. Expressed in Unix time, ecnoded as 4-byte unsigned int, 1-second time granularity (p. 348))*\
In order to derive the construction time, the following formula can be applied (Note: 4 byte unsigned int might not suffice to represent time in micro seconds):

    CT(sec) =   TS_inf + (TS * Floor((24*60*60)/2^32))
    CT(micsec)= TS_inf * 1'000'000 + (TS * Floor((24*60*60*1'000'000)/2^32))

### DRKeys

*For an exact defintion of DRKeys see scion/doc/DRKeyInfra.md*\
To efficiently derive symmetric keys between any two different ASes, EPIC makes use of SCIONs DRKey infrustructure. This mechanism avoids using asymmetric cryptography or state by applying pseudorandom functions. While one AS is always able to quickly derive the key on the fly, the other has to first gather some information. For efficiency reasons, EPIC uses the keys in such a way that the intermediate routers do not need aditional reasons while H_D first has to query its certificate server in order to obtain needed information. The procedure is described in the following:

#### K_i^S

*(short for K_{A_i -> A_0:H_S})*\
This is a symmetric key shared between host H_S in AS A_0 and AS A_i . It is quickly derivable for AS A_i.\
A_0:H_S has to perform the following steps to obtain the key:

    query local CS for key
    CS then:
        if key stored
            return key
        if K_{A_i -> A_0} stored
            return K_{A_i -> A_0:H_S}^{EPIC} = PRF_{K_{A_i -> A_0}}("EPIC"|H_S)
        else
            get K_{A_i -> A_0} from CS in A_i
            return K_{A_i -> A_0:H_S}^{EPIC} = PRF_{K_{A_i -> A_0}}("EPIC"|H_S)
    now key available

A_i the following:

    calculate key:
    K_{A_i -> A_0} = PRF_{SV_{A_i}}(A_0)
    K_{A_i -> A_0:H_S}^{EPIC} = PRF_{K_{A_i -> A_0}}("EPIC"|H_S)

#### K_{SD}

*(short for K_{A_D:H_D -> A_0:H_S}})*\
This is a symmetric key shared between host H_S in AS A_0 and host H_D in AS A_D. It is quickly derivable for A_D.\
A_0:H_S has to perform the following steps to obtain the key:

    query local CS for key
    CS then:
        if key stored
            return key
        if K_{A_D -> A_0} stored
            K_{A_D:H_D -> A_0:H_S}^{EPIC} = PRF_{K_{A_D -> A_0}}("EPIC"|H_D|H_S)
        else
            get K_{A_D -> A_0} from CS in A_D
            K_{A_D:H_D -> A_0:H_S}^{EPIC} = PRF_{K_{A_D -> A_0}}("EPIC"|H_D|H_S)
    now key available

A_D:H_D the following:

    query local CS for key
    CS then:
        derive key:
        K_{A_D -> A_0} = PRF_{SV_{A_D}}(A_0)
        K_{A_D:H_D -> A_0:H_S}^{EPIC} = PRF_{K_{A_D -> A_0}}("EPIC"|H_D|H_S)    


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

*(ExtType: So far, hop-by-hop (HBH) extensions up to 0x02 are already implemented. According to section 15.1.4 of the SCION book, 0x03 is reserved for One-Hop Path extension, which is however not implemented.)*

    Flags:
    r           unused
    s           source validation packet flag
    L           level

    TS          timestamp
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

    l           number of total hop validation fields
    i           number of current hop validation field
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
    l           number of total hop validation fields
    i           number of current hop validation field
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
    l           number of total hop validation fields
    i           number of current hop validation field
    V_{i,j}     Hop validation field for hop i after field j is processed
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
    l           number of total hop validation fields
    i           number of current hop validation field
    V_{i,j}     Hop validation field for hop i after field j is processed
                for i >  j: C_i^1 (^) C_{i-k}^3 {k = 2^z | 0<=z; k<=i-j}
                for i <= j: C_i^2
    C_i^a       MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[2*(a-1):2*a]

#### Source validation packet

Note: This type of packet is always sent from some Host H_D to another host H_S in order to validate an earlier packet from H_S to H_D.\
In this description here, fields referring to the packet H_D -> H_S are marked with a **'** at the end, while fields referring to the (original) packet H_S -> H_D are not.

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

    TS'            timestamp of packet H_D -> H_S
    PathHash'      H(Path')[0:4]
    PldHash'       H(Pld')[0:4]
    V_{SD}'        Source validation field
                   MAC_{K_{SD}}(TS'|H(Path')|H(Pld')|V_{1,l}|...|V_{l,l})[0:16]
    PathHash       H(Path)[0:4]
    PldHash        H(Pld)[0:4]
    TS             timestamp of packet H_S -> H_D
    l'             number of total hop validation fields for path H_D -> H_S
    i'             number of current hop validation field for path H_D -> H_S
    V_i'           Hop validation field for hop i'
                   H(TS'|PathHash'|PldHash'|$\sigma_i$')[0:2]
    V_{i,l}        Hop validation field for hop i at end of path H_S -> H_D
                   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[2:4]
                

### Procedure at source (H_S)

The source initializes all fields of the packet

#### How to get l

The number l can be obtained by counting all hop fields in the standard SCION path having the VRFY-ONLY flag not set.\
Note that it is not possible to directly use the SegLen fields of the info fields as hop fields can use more than 8 Bytes (continue flag).

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
    TS          see Definitions

    PathHash    H(Path)[0:4]
                Path = Forwarding Path in SCION header (p. 342)

    PldHash     H(Pld)[0:4]
                Pld = Layer-4 protocol and data (p. 342)

    l           number of total hop validation fields (see above how to derive)
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
    TS =        see Definitions

    PathHash =  H(Path)[0:4]
                Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
                Pld = Layer-4 protocol and data (p. 342)

    V_{SD} =    MAC_{K_{SD}}(TS|PathHash|PldHash)[0:16]

    l =         number of total hop validation fields (see above how to derive)
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
    TS =        see Definitions

    PathHash =  H(Path)[0:4]
                Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
                Pld = Layer-4 protocol and data (p. 342)

    l =         number of total hop validation fields (see above how to derive)
    i =         1

    for all i=1...l:
        C_i =   MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:4]
        V_{i,0} = C_i[0:2]
        V_{i,l} = C_i[2:4]

    V_{SD} =    MAC_{K_{SD}}(TS|PathHash|PldHash|V_{1,l}|...|V_{l,l})[0:16]

for the next step we need some kind of dict. (Also we need to store l, otherwise there is no efficient way to derive it):

    store V_{1,l},...,V_{l,l} in (dict(TS|PathHash|PldHash), l)

    send packet

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
    TS =        see Definitions

    PathHash =  H(Path)[0:4]
                Path = Forwarding Path in SCION header (p. 342)

    PldHash =   H(Pld)[0:4]
                Pld = Layer-4 protocol and data (p. 342)

    l =         number of total hop validation fields (see above how to derive)
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

    send packet

#### Level 3 & 4 receiving source validation packet

(NOTE: fields referring to the packet H_D -> H_S are marked with a **'** at the end, while fields referring to the (original) packet H_S -> H_D are not):


    if PathHash' != H(Path')[0:4] || PldHash' != H(Pld)[0:4]:
        validation failed
    if(current time(micsec)' - CT(micsec)') \notin acceptable lifetime:
        //see definitions for CT
        validation failed

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

#### How to handle i

The value stored in the i field always indicates which hop validation field we currently have to process. Depending on the flags and the border routers position either at the entry of an AS or at the exit of an AS, the value of i and for L3 and L4 V_i has to be adapted:\

    if packet enters AS:
        no flag: 
            no changes to V_i 
            i = i
        XOVER and no (PEER or SHORTCUT): 
            L3 and L4 manipulate V_i 
            i = i + 1
        XOVER and PEER: 
            no changes to V_i 
            i = i
        XOVER and SHORTCUT:
            L3 and L4 manipulate V_i 
            i = i + 1

    if packet leaves AS:
        L3 and L4 manipulate V_i
        i = i + 1


#### Level 1

(NOTE: fields referring to the packet H_D -> H_S are marked with a **'** at the end, while fields referring to the (original) packet H_S -> H_D are not)

    if(s = 0b0):
        if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
            //see definitions for CT
            validation failed

        get current i
        //i will be at a different place depending on s flag
        calculate $\sigma_i$
        if V_i != H(TS|PathHash|PldHash|$\sigma_i$)[0:2]:
            drop packet
        if needed, increment i
        forward packet

    else:
        if(current time(micsec)' - CT(micsec)') \notin acceptable lifetime:
            //see definitions for CT
            validation failed

        get current i
        //i will be at a different place depending on s flag
        calculate $\sigma_i$
        if V_i' != H(TS'|PathHash'|PldHash'|$\sigma_i$)[0:2]:
            drop packet
        if needed, increment i
        forward packet


#### Level 2

    if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
        //see definitions for CT
        validation failed

    get current i
    calculate $\sigma_i$
    calculate K_i^S
    if V_i != MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:2]:
        drop packet
    if needed, increment i
    forward packet



#### Level 3

    if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
        //see definitions for CT
        validation failed

    get current i
    calculate $\sigma_i$
    calculate K_i^S
    C = MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:4]
    if V_i != C[0:2]:
        drop packet
    if needed, increment i or/and replace V_i in packet with C[2:4]
    forward packet

#### Level 4

    if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
        //see definitions for CT
        validation failed

    get current i
    get l
    calculate $\sigma_i$
    calculate K_i^S
    C = MAC_{K_i^s}(TS|PathHash|PldHash|$\sigma_i$)[0:6]
    if V_i != C[0:2]:
        drop packet
    if needed, increment i or/and:
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

Procedure

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
        //see definitions for CT
        validation failed

    process payload

#### Level 2

Requirements:
* K_{SD}

Procedure

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
        //see definitions for CT
        validation failed

    if V_{SD} != MAC_{K_{SD}}(TS|H(Path)|H(Pld))[0:16]:
        drop packet

    process payload

#### Level 3 & 4

Requirements:
* K_{SD}
* $\sigma_i$ for all i=1...l' for path H_D -> H_S

Procedure

    if PathHash != H(Path)[0:4] || PldHash != H(Pld)[0:4]:
        drop packet
    if(current time(micsec) - CT(micsec)) \notin acceptable lifetime:
        //see definitions for CT
        validation failed

    if V_{SD} != MAC_{K_{SD}}(TS|H(Path)|H(Pld)|V_{1,l}|...|V_{l,l})[0:16]:
        drop packet

Create new Level 1 source validation packet:\
Payload of this packet could be used for other stuff...

Definition of fields and variables (NOTE: fields referring to the packet H_D -> H_S are marked with a **'** at the end, while fields referring to the (original) packet H_S -> H_D are not):

    NextHdr' =     type of next extension (already handled)
    HdrLen' =      5 + Ceil((2 + l' + l)/4)
    ExtType' =     0x03

ExtType: Implemented are HBH extensions up to 0x02, but maybe 0x03 is still already occupied

    Flags:
    s'=            0b1
    L'=            0b00

    TS' =          see Definitions

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
