# COLIBRI with EPIC

This document presents the changes to the COLIBRI protocol introduced through the combination with the EPIC extension.

* Author: Christopher Raffl
* Last updated: 2019-06-18
* Status: draft

### Content
* 1. Overview
* 2. Notation
* 3. Definitions and Derivations
    * 3.1 DRKeys
* 4. Design
    * 4.1 Changes to the current COLIBRI implementation 
* 5. Ideas / uncertainties / problems 

## 1. Overview

COLIBRI is an extension to the SCION architecture which introduces a mechanism for bandwidth reservations. Through the combination with the EPIC extenstion we aim to further increase its security properties. Mainly we want to achieve a per-packet source authentication mechanism.

## 2. Notation

    |           bitstring concatenation

    _           subscript
    ^           superscript

    K_i^{H_S}   K_{A_i -> A_S:H_S}^{COLIBRI} = symmetric key between host H_S in AS A_S and AS A_i for protocol COLIBRI
    K_i^S       K_{A_i -> A_S}^{COLIBRI} = symmetric key between AS A_S and AS A_i for protocol COLIBRI
    K_{SD}      K_{A_l:H_E -> A_S:H_S}^{COLIBRI} = symmetric key between host H_S in AS A_S and host H_E in AS A_E for protocol COLIBRI
    K_E^S       K_{A_E -> A_S}^{COLIBRI} = symmetric key between AS A_S and AS A_E for protocol COLIBRI
    SV_A        Local and AS-specific secret value of AS A 

    H(x)        Hash function of value x
    MAC_K(x)    Message authentication code using key K of value x
    PRF_K(x)    Pseudorandom function using key K and input x
    K(x)        Encryption function using key K and input x
    Floor(x)    Biggest integer value smaller than or equal to x
    x[a:b]      Substring from byte a (inclusive) to byte b (exclusive) of x

## 3 Definitions and Derivations

### 3.1 DRKeys

*For an exact defintion of DRKeys see scion/doc/DRKeyInfra.md*\
To efficiently derive symmetric keys between any two different ASes, we makes use of SCIONs DRKey infrustructure. This mechanism avoids using asymmetric cryptography or state by applying pseudorandom functions. While one AS is always able to quickly derive the key on the fly, the other has to first gather some information. For efficiency reasons, we use the keys in such a way that the intermediate border routers do not need aditional requests. Furthermore, since COLIBRI already leverages the DRKey infrastructure for setting up the reservations, the only additional key we further add is K_{SD}.\
The procedure of obtaining the required keys is described in the following:

#### K_i^{H_S}

*(short for K_{A_i -> A_S:H_S}^{COLIBRI})*\
This is a symmetric key shared between host H_S in AS A_S and AS A_i for protocol COLIBRI. It is quickly derivable for AS A_i.\
A_S:H_S has to perform the following steps to obtain the key:

    query local CS for key
    CS then:
        if key stored
            return key
        if K_{A_i -> A_S} not stored
            get it from CS in A_i
        return K_{A_i -> A_S:H_S}^{COLIBRI} = PRF_{K_{A_i -> A_S}}(COLIBRI|H_S)
    now key available

A_i the following:

    K_{A_i -> A_S} = PRF_{SV_{A_i}}(A_S)
    K_{A_i -> A_S:H_S}^{COLIBRI} = PRF_{K_{A_i -> A_S}}(COLIBRI|H_S)
    
#### K_i^S & K_E^S

*(short for K_{A_i -> A_S}^{COLIBRI}) and K_{A_E -> A_S}^{COLIBRI})*\
This is a symmetric key shared between AS A_S and AS A_i for protocol COLIBRI. It is quickly derivable for AS A_i.\
AS S has to perform the following steps to obtain the key:

    if key stored
        return key
    if K_{A_i -> A_S} not stored
        get it from CS in A_i
    return K_{A_i -> A_S}^{COLIBRI} = PRF_{K_{A_i -> A_S}}(COLIBRI)

A_i the following:

    K_{A_i -> A_S} = PRF_{SV_{A_i}}(A_S)
    K_{A_i -> A_S}^{COLIBRI} = PRF_{K_{A_i -> A_S}}(COLIBRI)

For K_E^S replace AS i with AS E in all occurences above.

#### K_{SD}

*(short for K_{A_E:H_E -> A_S:H_S}^{COLIBRI})*\
This is a symmetric key shared between host H_S in AS A_S and host H_E in AS A_E for protocol COLIBRI. It is quickly derivable for A_E.\
A_S:H_S has to perform the following steps to obtain the key:

    query local CS for key
    CS then:
        if key stored
            return key
        if K_{A_E -> A_S} not stored
            get it from CS in A_E
        return K_{A_E:H_E -> A_S:H_S}^{COLIBRI} = PRF_{K_{A_E -> A_S}}(COLIBRI|H_E|H_S)
    now key available

A_E:H_E the following:

    query local CS for key
    CS then:
        if key stored
            return key
        K_{A_E -> A_S} = PRF_{SV_{A_E}}(A_S)
        return K_{A_E:H_E -> A_S:H_S}^{COLIBRI} = PRF_{K_{A_E -> A_S}}(COLIBRI|H_E|H_S)


## 4 Design

### 4.1 Changes to the current COLIBRI implementation

To the already existing packet design we will add further fields enabling each border router to authenticate and uniquely identify each packet:
* Destination Validation Field (V_{SD})(16 Bytes): 1 per packet
* Payload Hash (PldHash)(4 Bytes): 1 per packet
* Timestamp (TS)(4 Bytes): 1 per packet

Furthermore we will change the following:
* Modify computation of MAC of opaque field in reservation token creating process
* Modify MAC of opaque fields when sending packets by inserting Hop Verification Fields
* Remove Timestamp in COLIBRI request payload except for segment reservation request packets.

#### Destination Validation Field

This field will be inserted right after the first 8 bytes of the extension header. By adding a 16-byte field MAC over the Timestamp, the Hash of the Payload and all reservation IDs we add a high level of unforgeability. Adding reservation tokens would add no more security to packets with active reservation tokens, since the reservation IDs are already included in the MACs of the opaque fields. For segment request packets on the other hand, which do not have active reservation tokens, it makes sense to replace this with a Hash over the SCION path to bind the path to the packet.\
This field is computed by the source host while sending the packet and checked by the destination host when receiving the packet.

    Non segment setup request packets sent on end-to-end reservations:
    V_{SD} =    MAC_{K_{SD}}(TS|H(Pld)|Reservation IDs(1-4))[0:16]

    Non segment setup request packets sent onsegment reservations:
    V_{SD} =    MAC_{K_{SD}}(TS|H(Pld)|Reservation IDs(1-4))[0:16]

    Segment setup request packets:
    V_{SD} =    MAC_{K_E^S}(TS|H(Pld)|H(Path))[0:16]


#### Payload Hash

This field will be inserted right after V_{SD}. For non-request packets it is just a simple 4 byte hash computed over the payload of the packet. Since the payload of request packets is modified along the path, we only include the immutable part of it. The purpose of this field is to bind the payload to the rest of the packet and prevent attackers from tampering with the payload.\
This field is computed by the source host while sending the packet and for efficiency reasons only checked by the destination host when receiving the packet. 

    Non-request packets:
    PldHash =   H(Pld)[0:4]

    Request packets:
    PldHash =   H(Pld(immutable))[0:4]

#### Timestamp

The Timestamp is inserted right after the Payload Hash. Since both those fields are 4 bytes, together they fit the 8-byte aligning required for SCION extensions. For all packets but segment setup requests, the timestamp encodes the construction time of the packet relative to the expiration time defined in the first reservation token in a 4 byte unsigned int. Since end-to-end reservations are only valid up to 4 COLIBRI ticks (=16 seconds), using 4 bytes results in a granularity of about 3.73 ns. Assuming a packet size of at least 544 bits(which is very conservative **TODO:** Update this value an show calculation), this enables us to uniquely identify all packets on a link with a bandwidth of up to 145 Gbit/s. Segment reservations are valid up to 80 COLIBRI ticks (~5 minutes), which gives us a granularity of about 74.6 ns. Since segment reservations should not be used for excessive amounts of traffic, this should also suffice to uniquely determine each packet. Packets including requests as payloads already have a timestamp PldTS in the payload field in the current implementation. It indicates the construction time in seconds since the unix epoch. Since all requests apart from the segment setup request also have at least one active reservation token, they have an expiration time field we can use for the Timestamp. Thus, the current timestamp PldTS does not provide any further information and will be removed for all request packets except for segment setup request packets. These packets have a non-empty SCION path and thus also an extra field indicating the expiration time of the path. However, if we made our TS dependent on this, the resulting granularity would be about 100 ms which does not suffice for our purposes. As a consequence we will keep the PldTS for this case and encode the time in TS relative to this field.\
The possibility for all border routers to uniquely define each packet using its TS and source address gives us a good starting point for building a packet replay suppression mechanism. Through the checks the authenticity of this information can be veryfied by each border router.\
The timestamp is computed by the source host while sending and checked by each border router as well as the desination host.

    End-to-end reservations:
    TS =        Floor((ExpTime - CT) * (2^32/16'000'000'000))

    Segment reservations:
    TS =        Floor((ExpTime - CT) * (2^32/320'000'000'000))

    Segment setup request packets:
    TS =        Floor((CT - PldTS) * (2^32/320'000'000'000))

        where:
            CT =        Construction time in nanoseconds
            ExpTime =   Expiration time of first reservation token * 4'000'000'000
            PldTS =     Timestamp in Payload * 1'000'000'000

#### Modified computation of MAC of opaque fields in reservation token creating process

In order to modify the MACs in the reservation tokens such that they also include the Hop Verficiation Field (see below), we have to change their computation during their creation. When sending normal data packets, we will only send the first two bytes of the MAC field. Thus, when  including the previous opaque field we have to ignore all other bytes of its MAC. Furthermore, we will encrypt the MAC with a symmetric key shared between AS A_i and the source host. By doing so, we prevent other hosts on the path to reuse the observed information. Let us define the encrypted MAC of the i-th opaque field as encrpyted hop authenticator (HA_i^{e}) and the decrpyted MAC of the i-th field as decrypted hop authenticator (HA_i^{d}). Note that we include the full MAC without truncation. Then the opaque field during reservation token creating process will look as follows:

    OF_i = IngressIFID_i | EgressIFID_i | HA_i^{e}

        where:
            HA_i^{e} 
            = K_{SV_{A_i}}(MAC_{K_{SV_{A_i}}}(IngressIFID_i | EgressIFID_i | SteadyInfo | OF_{prev}[0:6]))


#### Modified MAC of opaque fields when sending packets by inserting Hop Verification Fields

For each opaque field i, a 2 byte hop verification field V_i will be included when sending a packet. They will replace the last two bytes of the field, reducing the length of the previous MAC. In this way, no further overhead is added to the packet. The purpose of this field is to enable border routers to authenticate each packet as well as the integrity of the most important fields. This prevents attackers from e.g. using once observed paths with different payloads. In the computation of the V_i we include all the fields that are relevant to be able to bind this specific packet to this reservation at this point in time with this certain payload. Also assuming a packet replay suppression mechanism being established, there is no possibility for an attacker to reuse parts of a once observed packet. Furthermore by including the full HA_i^{d} in its decrypted version in the computation we enable each border router R_i to authenticate the path traversed in the corresponding AS A_i and prevent other ASes on the path to missuse the hop. For border router R_i to be able to recalculate and validate the hop verification field V_i it needs the encrypted version of the first two bytes of the MAC of the previous hop (see above). Also notice that each border router is able to recompute its corresponding hop authenticator and thus not the full version needs to be included. The hop verification fields are computed by the source host. Each border router then checks its corresponding field.\
Since segment setup requests do not have active reservation tokens but use the normal SCION path fields, we have to use another method for those packets. Each hop on the way checks anyway if the chosen path corresponds to its policies while processing the request. Therefore, the non-existence of hop authenticators does not result in a problem. To still bind all information together, we include a Hash over the SCION path (PathHash) in the computation. The hop verification fields will be insterted at the place where in other packets the reservation tokens are situated.

    Non segment setup request packets on end to end reservations:
    OF_i = IngressIFID_i | EgressIFID_i | HA_i^{e}[0:2] | V_i
        where:
            V_i =   MAC_{K_i^{H_S}}(TS|PldHash|HA_i^{d})[0:2]

    Non segment setup request packets on segment reservations:
    OF_i = IngressIFID_i | EgressIFID_i | HA_i^{e}[0:2] | V_i
        where:
            V_i =   MAC_{K_i^S}(TS|PldHash|HA_i^{d})[0:2]

    Segment setup request packet:
    V_i = MAC_{K_i^S}(TS|PldHash|PathHash)[0:2]
        where:
            PathHash = H(SCION-Path)

## 5 Ideas / uncertainties / problems

* (6/6 rafflc) Instead of introducing the same mechanism for the request fields, maybe it would make sense to modify the already existing authenticator fields in the request payload. However, checking Authenticators at the border routers possibly reduces performance, while introducing these additional fields only brings little overhead reagarding packet size (except for segment setup requests).\
Also I am not sure if these authenticators already include the whole packet or only the request payload.\
(6/11 rafflc) After discussing with Dominik: Bad idea. Authenticators only authenticate payload
* (6/6 rafflc) Maybe we can add a mechanism that makes it optional to use the V_{SD} or at least think about different sizes.
* (6/12 rafflc) Do we really need onion authentication?
* (6/12 rafflc) Can't we just use a hash for computing the V_i? But only for non segment setup request packets on end to end reservations?