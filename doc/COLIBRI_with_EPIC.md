# COLIBRI with EPIC

This document presents the changes to the COLIBRI protocol introduced through the combination with the EPIC extension

* Author: Christopher Raffl
* Last updated: 2019-06-05
* Status: draft

## Overview

COLIBRI is an extension to the SCION architecture which introduces a mechanism for bandwidth reservations. Through the combination with the EPIC extenstion we aim to further increase its security properties. Mainly we want to achieve a per-packet source authentication mechanism.

## Notation

    |           bitstring concatenation

    _           subscript
    ^           superscript

    K_i^S       K_{A_i -> A_0:H_S} = symmetric key between host H_S in AS A_0 and AS A_i
    K_{SD}      K_{A_l:H_D -> A_0:H_S} = symmetric key between host H_S in AS
                A_0 and host H_D in AS A_l
    SV_A        Local and AS-specific secret value of AS A

    H(x)        Hash function of value x
    MAC_K(x)    Message authentication code using key K of value x
    PRF_K(x)    Pseudorandom function using key K and input x
    x[a:b]      Substring from byte a (inclusive) to byte b (exclusive) of x

## Definitions and Derivations

### DRKeys

*For an exact defintion of DRKeys see scion/doc/DRKeyInfra.md*\
To efficiently derive symmetric keys between any two different ASes, we makes use of SCIONs DRKey infrustructure. This mechanism avoids using asymmetric cryptography or state by applying pseudorandom functions. While one AS is always able to quickly derive the key on the fly, the other has to first gather some information. For efficiency reasons, we use the keys in such a way that the intermediate border routers do not need aditional requests. Furthermore, since COLIBRI already leverages the DRKey infrastructure for setting up the reservations, the only additional key we further add is K_{SD}.\
The procedure of obtaining the required keys is described in the following:

#### K_i^S

*(short for K_{A_i -> A_0:H_S})*\
This is a symmetric key shared between host H_S in AS A_0 and AS A_i . It is quickly derivable for AS A_i.\
A_0:H_S has to perform the following steps to obtain the key:

    query local CS for key
    CS then:
        if key stored
            return key
        if K_{A_i -> A_0} stored
            return K_{A_i -> A_0:H_S} = PRF_{K_{A_i -> A_0}}(H_S)
        else
            get K_{A_i -> A_0} from CS in A_i
            return K_{A_i -> A_0:H_S} = PRF_{K_{A_i -> A_0}}(H_S)
    now key available

A_i the following:

    get SV_{A_i} from CS
    K_{A_i -> A_0} = PRF_{SV_{A_i}}(A_0)
    K_{A_i -> A_0:H_S} = PRF_{K_{A_i -> A_0}}(H_S)

#### K_{SD}

*(short for K_{A_l:H_D -> A_0:H_S}})*\
This is a symmetric key shared between host H_S in AS A_0 and host H_D in AS A_l. It is quickly derivable for A_0:H_S.\
A_0:H_S has to perform the following steps to obtain the key:

    query local CS for key
    CS then:
        if key stored
            return key
        if K_{A_l -> A_0} stored
            K_{A_l:H_D -> A_0:H_S} = PRF_{K_{A_l -> A_0}}(H_D|H_S)
        else
            get K_{A_l -> A_0} from CS in A_l
            K_{A_l:H_D -> A_0:H_S} = PRF_{K_{A_l -> A_0}}(H_D|H_S)
    now key available

A_l:H_D the following:

    get SV_{A_l} from CS
    K_{A_l -> A_0} = PRF_{SV_{A_l}}(A_0)
    K_{A_l:H_D -> A_0:H_S} = PRF_{K_{A_l -> A_0}}(H_D|H_S)


## Design

### Changes to the current COLIBRI implementation

To the already existing packet design we will add further fields enabling each border router to authenticate and uniquely identify each packet:
* Destination Validation Field (V_{SD})(16 Bytes): 1 per packet
* Payload Hash (PldHash)(4 Bytes): 1 per packet
* Timestamp (TS)(4 Bytes): 1 per packet
* Hop Verification Field (V_i): 1 per hop

#### Destination Validation Field

This field will be inserted right after the first 8 bytes of the extension header. By adding a 16-byte field MAC over the Timestamp, the Hash of the Payload and all reservation IDs we add a high level of unforgeability. Adding reservation tokens would add no more security to packets with active reservation tokens, since the reservation IDs are already included in the MACs of the opaque fields. For segment request packets on the other hand, which do not have active reservation tokens, it makes sense to replace this with a Hash over the SCION path to bind the path to the packet.\
This field is computed by the source host while sending the packet and checked by the destination host when receiving the packet.

    Non segment reservation packets:
    V_{SD} =    MAC_{K_{SD}}(TS|H(Pld)|Reservation IDs(1-4))[0:16]

    Segment reservation packets:
    V_{SD} =    MAC_{K_{SD}}(TS|H(Pld)|H(Path))[0:16]

#### Payload Hash

This field will be inserted right after V_{SD}. For non-request packets it is just a simple 4 byte hash computed over the payload of the packet. Since the payload of request packets is modified along the path, we only include the immutable part of it. The purpose of this field is to bind the payload to the rest of the packet and prevent attackers from tampering with the payload.\
This field is computed by the source host while sending the packet and for efficiency reasons only checked by the destination host when receiving the packet. 

    Non-request packets:
    PldHash =   H(Pld)[0:4]

    Request packets:
    PldHash =   H(Pld(immutable))[0:4]

#### Timestamp

The Timestamp is insterted right after the Payload Hash. Since both those fields are 4 bytes, together they fit in the 8-byte aligning required for SCION extensions. For non-request packets, the timestamp encodes the construction time of the packet relative to the expiration time defined in the first reservation token in a 4 byte unsigned int. Since end-to-end reservations are only valid up to 4 COLIBRI ticks (=16 seconds), using 4 bytes results in a granularity of about 3.73 ns. Assuming a packet size of at least 544 bits(which is very conservative), this enables us to uniquely identify all packets on a link with a bandwidth of up to 145 Gbit/s. Segment reservations are valid up to 80 COLIBRI ticks (~5 minutes), which gives us a granularity of about 74.6 ns. Since segment reservations should not be used for excessive amounts of traffic, this should also suffice to uniquely determine each packet. Packets including requests as payloads already have a timestamp PldTS in the payload field with a granularity of 1 second. Since this is not enough, we also need an additional timestamp. Here we could further decrease the granularity, but for simplicity we stick to the granularity of 3.73 ns\
The possibility for all border routers to uniquely define each packet using its TS and source address gives us a good starting point for building a packet replay suppression mechanism. Through the checks the authenticity of this information can be varyfied by each border router.\
The timestamp is computed by the source host while sending and checked by each border router as well as the desination host.

    End-to-end reservations:
    TS =        (ExpTime - CT) * Floor(2^32/16'000'000'000)

    Segment reservations:
    TS =        (ExpTime - CT) * Floor(2^32/320'000'000'000)

    Request packets:
    TS =        (CT + PldTS) * Floor(2^32/320'000'000'000)

        where:
            CT =        Construction time in nanoseconds
            ExpTime =   Expiration time of first reservation token * 4'000'000'000
            PldTS =     Timestamp in Payload * 1'000'000'000

#### Hop Verification Field

For each opaque field, a 2 byte hop verification field will be added to the reservation tokens when sending a packet. The purpose of this field is to enable border routers to authenticate each packet and the integrity of the most important fields and thus preventing attackers from e.g. using once observed paths with different payloads. In the computation of the MAC we include all the field that are relevant to be able to bin this specific packet to this reservation at this point in time with this certain payload. Also assuming a packet replay suppression mechanism being established, there is no possibility for an attacker to reuse parts of a once observed packet. Again, for segment request reservations we have to use a substitute for the opaque fields. Since all hops on the way check anyway if the requested path is legal, the only purpose in that case is to bind the information together. Thus we will just use again a Hash over the SCION path and the MAC of the corresponding hop field.

    Non segment reservation packets:
    V_i =       MAC_{K_i^s}(TS|PldHash|MAC of OF_i)[0:2]

    Segment reservation packets:
    V_i =       MAC_{K_i^s}(TS|PldHash|PathHash|MAC of HF_i)[0:2]
