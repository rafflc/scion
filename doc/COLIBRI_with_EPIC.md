# COLIBRI with EPIC

This document presents the changes to the COLIBRI protocol introduced through the combination with the EPIC extension

* Author: Christopher Raffl
* Last updated: 2019-06-03
* Status: draft

## Overview

COLIBRI is an extension to the SCION architecture which introduces a mechanism for bandwidth reservations. Through the combinatio with the EPIC extenstion we aim to further increasing its security properties.

## Design

### Changes to the current COLIBRI implementation

In order to _something_ we add hop validation field of 2 bytes for each hop, i.e. opaque field.\

    V_i:    MAC_{K_i^s}(TS|PldHash|MAC_i)[0:2]
    V_i:    MAC_{K_i^s}(TS|PldHash|MAC_i)[0:2]

aklsdjf

    0                   1                   2                   3
    0  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |NextHdr|HdrLen | 0x02  | flags |       |       |       |       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       |       |       |       |       |       |       |       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
    |       |       |       |       |       |       |       |       |    1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            PldHash                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----

Furthermore, the COLIBRI extension header gets in addition three extra fields:\
Right after the P2 Hops field and before the Reservation IDs we add the following fields:\
* Destination validation field (V_SD)(16 Bytes): Allows the destination of a packet to perform source authentication and path validation.

        V_{SD}:     MAC_{K_{SD}}(TS|H(Pld)|Reservation IDs(1-4))[0:16]

* Payload Hash (PldHash)(4 Bytes): This is a hash over the payload

        PldHash:    H(Payload)

* Timestamp (TS)(4 Bytes): The timestamp encodes the construction time of the packet relative to the expiration time defined in the first reservation token. Since end-to-end reservations are only valid up to 4 COLIBRI ticks (=16 seconds), using 4 bytes results in a granularity of about 3.73 ns. Assuming a packets size of at least 544 bits, this enables us to uniquely identify all packets on a link with a bandwidth of up to 145 Gbit/s. Segment reservations are valid up to 80 COLIBRI ticks (~5 minutes), which gives us a granularity of about 74.6 ns. Since we do not expect packets being sent on a segment reservation on a high rate, this also suffices to let us identify each packet uniquely    
