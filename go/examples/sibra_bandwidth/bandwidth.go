// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/l4"

	"context"

	"encoding/csv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/sbextn"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/sibrad/resvmgr"
)

const (
	DefaultInterval = 1 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxPings        = 1 << 16
	ReqMsg          = "ping!" // ReqMsg and ReplyMsg length need to be the same
	ReplyMsg        = "pong!"
	TSLen           = 8
	ModeServer      = "server"
	ModeClient      = "client"
)

var (
	local  snet.Addr
	remote snet.Addr
	file   = flag.String("file", "",
		"File containing the data to send, optional to test larger data (only client)")
	interactive = flag.Bool("i", false, "Interactive mode")
	flush       = flag.Bool("f", false, "flush paths")
	id          = flag.String("id", "pingpong", "Element ID")
	mode        = flag.String("mode", ModeClient, "Run in "+ModeClient+" or "+ModeServer+" mode")
	sciond      = flag.String("sciond", "", "Path to sciond socket")
	dispatcher  = flag.String("dispatcher", "", "Path to dispatcher socket")
	count       = flag.Int("count", 0,
		fmt.Sprintf("Number of pings, between 0 and %d; a count of 0 means infinity", MaxPings))
	timeout = flag.Duration("timeout", DefaultTimeout,
		"Timeout for the ping response")
	interval     = flag.Duration("interval", DefaultInterval, "time between pings")
	bwCls        = flag.Uint("bw", 5, "bandwidth class")
	verbose      = flag.Bool("v", false, "sets verbose output")
	sciondFromIA = flag.Bool("sciondFromIA", false,
		"SCIOND socket path from IA address:ISD-AS")
	wl4 = flag.String("wl4", "0-0,[0.0.0.0/0]", "Whitelisted IPv4 subnets. All reservations"+
		"are accepted by default.")
	wl6 = flag.String("wl6", "0-0,[::/0]", "Whitelisted IPv6 subnets. All reservations"+
		"are accepted by default.")

	// My modifications
	mtu            = flag.Uint("packetSize", 800, "UDP packet payload size")
	duration       = flag.Uint("duration", 5, "Duration of test (in seconds)")
	bandwidth      = flag.Uint("bandwidth", 1024, "Bandwidth at which to send data (bytes per second)")
	useSibra       = flag.Bool("sibra", true, "Use sibra paths")
	paceFile       = flag.String("pf", "", "File containing packet sizes and timings for reproducing existing flow")
	repeatFlowFile = flag.Int("repeat", 1, "Number of times to repeat the flow file data")

	fileData []byte
)

func init() {
	flag.Var((*snet.Addr)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	log.AddLogConsFlags()
	log.SetupLogConsole("debug")
	validateFlags()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.LogPanicAndExit()
	initNetwork()
	switch *mode {
	case ModeClient:
		if remote.Host == nil {
			LogFatal("Missing remote address")
		}
		if remote.L4Port == 0 {
			LogFatal("Invalid remote port", "remote port", remote.L4Port)
		}
		c := newClient()
		setSignalHandler(c)
		c.run()
	case ModeServer:
		server{}.run()
	}
}

func validateFlags() {
	flag.Parse()
	if *mode != ModeClient && *mode != ModeServer {
		LogFatal("Unknown mode, must be either '" + ModeClient + "' or '" + ModeServer + "'")
	}
	if *mode == ModeClient && remote.Host == nil {
		LogFatal("Missing remote address")
	}
	if local.Host == nil {
		LogFatal("Missing local address")
	}
	if *sciondFromIA {
		if *sciond != "" {
			LogFatal("Only one of -sciond or -sciondFromIA can be specified")
		}
		if local.IA.IsZero() {
			LogFatal("-local flag is missing")
		}
		*sciond = sd.GetDefaultSCIONDPath(&local.IA)
	} else if *sciond == "" {
		*sciond = sd.GetDefaultSCIONDPath(nil)
	}
	if *count < 0 || *count > MaxPings {
		LogFatal("Invalid count", "min", 0, "max", MaxPings, "actual", *count)
	}
	if *file != "" {
		if *mode == ModeClient {
			var err error
			fileData, err = ioutil.ReadFile(*file)
			if err != nil {
				LogFatal("Could not read data file")
			}
		} else {
			log.Info("file argument is ignored for mode " + ModeServer)
		}
	}
	if _, err := resvmgr.NetFromString(*wl4); err != nil {
		LogFatal("Invalid IPv4 whitelist subnet", err)
	}
	if _, err := resvmgr.NetFromString(*wl6); err != nil {
		LogFatal("Invalid IPv6 whitelist subnet", err)
	}
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}

func initNetwork() {
	// Initialize default SCION networking context
	// FIX: Sometimes init fails, so we try to do it 5 times
	for initAtempts := 5; initAtempts >= 0; initAtempts-- {
		if err := snet.Init(local.IA, *sciond, *dispatcher); err != nil {
			LogFatal("Unable to initialize SCION network", "err", err)
			time.Sleep(time.Millisecond * 100)
			continue
		}
		break
	}
	log.Debug("SCION network successfully initialized")
}

type client struct {
	sess     *snet.Conn
	mgr      *resvmgr.Mgr
	clientId uint64
}

func newClient() *client {
	return &client{}
}

// run dials to a remote SCION address and repeatedly sends ping messages
// while receiving pong messages. For each successful ping-pong, a message
// with the round trip time is printed.
func (c *client) run() {
	fmt.Println("Starting client")
	c.initResvMgr()

	var packetTimings []packetTiming = nil
	var testDuration time.Duration
	var maxPacketLength int
	var bwClass sibra.BwCls = sibra.BwCls(*bwCls)
	if *paceFile != "" {
		packetTimings, testDuration, maxPacketLength, bwClass = loadPaceFile(*paceFile)
	}

	// Needs to happen before DialSCION, as it will 'copy' the remote to the connection.
	// If remote is not in local AS, we need a path!
	ws := c.setupPath(*useSibra, bwClass)
	defer c.Close()
	fmt.Println("Created ws")
	// Connect to remote address. Note that currently the SCION library
	// does not support automatic binding to local addresses, so the local
	// IP address needs to be supplied explicitly. When supplied a local
	// port of 0, DialSCION will assign a random free local port.
	var err error
	c.sess, err = snet.DialSCION("udp4", &local, &remote)
	if err != nil {
		LogFatal("Unable to dial", "err", err)
	}
	fmt.Println("Finished dialing scion")
	quit := make(chan struct{})
	if ws != nil {
		ws.DrainEvents(quit)
	}

	fmt.Println("Creating channels")
	rcvChannel := make(chan common.RawBytes)
	go c.read(rcvChannel) // Reading all messages that are coming
	fmt.Println("Created read goroutine")

	var droppedPacktes uint64 = 0
	var testId uint64
	var packetNumber uint64
	if packetTimings != nil {
		packetNumber = uint64(len(packetTimings)) * uint64(*repeatFlowFile)
		testId = c.registerNewTest(uint64(packetNumber), testDuration, maxPacketLength, rcvChannel)
		if *repeatFlowFile < 0 {
			for {
				c.sendDataFromFile(packetTimings, testId, testDuration, maxPacketLength)
			}
		} else {
			for i := 0; i < int(*repeatFlowFile); i++ {
				droppedPacktes += c.sendDataFromFile(packetTimings, testId, testDuration, maxPacketLength)
			}
		}

	} else {
		var pace time.Duration
		packetNumber, pace = calculatePacketCount(*bandwidth, *duration, *mtu)
		testId = c.registerNewTest(uint64(packetNumber), time.Duration(*duration)*time.Second, 800, rcvChannel)
		droppedPacktes = c.sendDataConstantRate(uint64(packetNumber), uint64(pace), testId, uint64(*duration))
	}
	droppedPacktes += c.GetTestStatus(testId, rcvChannel)
	c.DisplayResults(uint64(packetNumber), droppedPacktes, uint64(*duration))
}

func calculatePacketCount(bandwidth, seconds, packetSize uint) (uint64, time.Duration) {
	log.Debug("Calculating pace", "desired_bandwidth", bandwidth, "test_duration", seconds, "packet_size", packetSize)

	totalData := bandwidth * seconds
	totalPackets := totalData / (packetSize + l4.UDPLen)
	pace := time.Duration(seconds * uint(time.Second) / totalPackets)
	return uint64(totalPackets), pace
}

func (c *client) registerNewTest(packetNumber uint64, duration time.Duration, maxPacketLength int, rcvChannel <-chan common.RawBytes) uint64 {
	fmt.Println("Registring new test!")
	msg := &MsgCreateTest{
		Packets:  packetNumber,
		Duration: uint64(duration),
		Mtu:      uint64(maxPacketLength),
	}
	buf := make(common.RawBytes, maxPacketLength)
	buf = msg.Pack(buf)
	_, err := c.sess.Write(buf)
	if err != nil {
		log.Error("Unable to write", "err", err)
	}
	buf = ReceiveMessage(rcvChannel, TestCreated)
	var tc MsgTestCreated
	tc.Unpack(buf)
	return tc.SessionId
}

func (c *client) sendDataFromFile(timings []packetTiming, sessionId uint64, testDuration time.Duration, maxPacketSize int) uint64 {
	const HEADER_SIZE = 120 //TODO: Verify header size

	sendBuffer := make(common.RawBytes, maxPacketSize)
	dataMsg := MsgPayload{
		SessionId:   sessionId,
		PacketIndex: 0,
	}

	log.Debug("Sending data from provided flow info file", "test_duration", testDuration, "max_packet_size", maxPacketSize)

	packetNumber := len(timings)
	lastPacketSent := time.Now()

	endDeadline := time.Now().Add(testDuration)

	var pn int
	for pn = 0; pn < packetNumber; pn++ {
		now := time.Now()

		if endDeadline.Before(now) {
			log.Warn("Time limit exceeded! Couldn't send all the messages", "packet_number", packetNumber, "sentPackets", pn)
			break
		}

		packetSize := max(dataMsg.Size(), timings[pn].packetSize-HEADER_SIZE)
		timeForPacket := lastPacketSent.Add(timings[pn].sleepBeforeSend)
		if now.Before(timeForPacket) {
			time.Sleep(timeForPacket.Sub(now))
		}

		dataMsg.PacketIndex = uint64(pn)
		dataMsg.Pack(sendBuffer)

		_, err := c.sess.Write(sendBuffer[:packetSize])
		if err != nil {
			log.Error("Unable to write", "err", err)
		}
		lastPacketSent = time.Now()
	}

	return uint64(packetNumber - pn - 1)
}

func (c *client) sendDataConstantRate(packetNumber, pace, sessionId, totalTime uint64) uint64 {
	sendBuffer := make(common.RawBytes, *mtu)
	dataMsg := MsgPayload{
		SessionId:   sessionId,
		PacketIndex: 0,
	}

	nextPacketScheduled := time.Now()
	nextPacketScheduled = nextPacketScheduled.Add(time.Duration(pace))

	log.Debug("Sending packets with pace of", "time", time.Duration(pace))

	endDeadline := time.Now().Add(time.Duration(totalTime) * time.Second)

	var pn uint64
	for pn = uint64(0); pn < packetNumber; pn++ {
		now := time.Now()

		//var dropThisPacket bool = false

		//lastDeadline := nextPacketScheduled.Add(time.Duration(pace))
		//if now.After(lastDeadline){
		//	dropThisPacket=true
		//}
		if endDeadline.Before(now) {
			log.Warn("Time limit exceeded! Couldn't send all the messages", "packet_number", packetNumber, "sentPackets", pn)
			break
		}

		nextPacketScheduled = nextPacketScheduled.Add(time.Duration(pace))

		dataMsg.PacketIndex = pn
		//if dropThisPacket {
		//	// Dropping packet to keep up the pace
		//	continue
		//}
		dataMsg.Pack(sendBuffer)

		_, err := c.sess.Write(sendBuffer)
		if err != nil {
			log.Error("Unable to write", "err", err)
		}
		now = time.Now()

		if now.Before(nextPacketScheduled) {
			time.Sleep(nextPacketScheduled.Sub(now))
		}
	}

	return (packetNumber - pn) - 1
}

func (c *client) GetTestStatus(sessionId uint64, rcvChannel <-chan common.RawBytes) uint64 {
	time.Sleep(time.Second)
	msg := &MsgTestEnd{
		SessionId: sessionId,
	}
	buf := make(common.RawBytes, msg.Size())
	buf = msg.Pack(buf)
	_, err := c.sess.Write(buf)
	if err != nil {
		log.Error("Unable to write", "err", err)
	}
	buf = ReceiveMessage(rcvChannel, TestResult)
	var res MsgTestResult
	res.Unpack(buf)
	return res.DroppedPackets
}

func (c *client) DisplayResults(packetNumber, droppedPackets uint64, testDuration uint64) {
	dropRate := float64(droppedPackets*100) / float64(packetNumber)
	sentData := (packetNumber - droppedPackets) * (uint64)(*mtu)
	bps := sibra.Bps(float64(sentData) / float64(testDuration))
	fmt.Println(fmt.Sprintf("We sent: %d packets and dropped: %d packets. Drop rate: %f", packetNumber, droppedPackets, dropRate))
	fmt.Fprintf(os.Stderr, "Speed: %s drop rate: %f\n", bps.String(), dropRate)
}

func (c *client) initResvMgr() {
	saddr := local.Copy()
	saddr.L4Port = sibra.Port
	conn, err := snet.ListenSCIONWithBindSVC("udp4", saddr, nil, addr.SvcNone)
	if err != nil {
		LogFatal("Unable to listen snet", "err", err)
	}
	db, err := trustdb.New("testdb.sql")
	if err != nil {
		LogFatal("Unable to initialize trustdb", "err", err)
	}
	store, err := trust.NewStore(db, local.IA, 0, nil, log.Root())
	if err != nil {
		LogFatal("Unable to create trust store", "err", err)
	}
	for retry := 5; retry >= 0; retry-- {
		c.mgr, err = resvmgr.New(snet.DefNetwork.Sciond(), conn, store, nil)
		if err != nil {
			log.Warn("Unable to start reservation manager", err)
			time.Sleep(time.Millisecond * 100)
			continue
		}
		break
	}
}

func (c *client) Close() error {
	var err error
	if c.sess != nil {
		err = c.sess.Close()
	}
	return err
}

func (c client) setupPath(sibra bool, bwClass sibra.BwCls) *resvmgr.WatchState {
	if sibra {
		log.Info("Configuring path with SIBRA")
		if !remote.IA.Eq(local.IA) {
			if *flush {
				if err := c.flushPath(); err != nil {
					LogFatal("Unable to flush", "err", err)
				}
			}
			pathEntry, ws := c.choosePathWithSibra(*interactive, bwClass)
			if pathEntry == nil {
				LogFatal("No paths available to remote destination")
			}
			remote.Path = spath.New(pathEntry.Path.FwdPath)
			remote.Path.InitOffsets()
			remote.SibraResv = ws.SyncResv
			remote.NextHopHost = pathEntry.HostInfo.Host()
			remote.NextHopPort = pathEntry.HostInfo.Port
			log.Info("sibrevs", "watchState", ws, "remote", remote.SibraResv)
			return ws
		}
	} else {
		log.Info("Configuring path WITHOUT SIBRA")
		if !remote.IA.Eq(local.IA) {
			pathEntry := choosePath(*interactive)
			if pathEntry == nil {
				LogFatal("No paths available to remote destination")
			}
			remote.Path = spath.New(pathEntry.Path.FwdPath)
			remote.Path.InitOffsets()
			remote.NextHopHost = pathEntry.HostInfo.Host()
			remote.NextHopPort = pathEntry.HostInfo.Port
		}
		return nil
	}

	return nil
}

func (c client) read(receivedPackets chan<- common.RawBytes) {
	// 100 bytes should be enough since these are only control messages
	buf := make(common.RawBytes, 100)

	fmt.Println("Starting to read packets")
	for {
		_, err := c.sess.Read(buf)
		if err == nil {
			fmt.Println("Got a packet!")
			switch messageType := common.Order.Uint64(buf); messageType {
			case TestCreated:
				res := make(common.RawBytes, len(buf))
				copy(res, buf)
				receivedPackets <- res
			case TestResult:
				res := make(common.RawBytes, len(buf))
				copy(res, buf)
				receivedPackets <- res
			default:
				log.Debug("Unknown message received", "messageType", messageType)
			}
		} else {
			log.Error("Reading packets", "Error", err)
		}
	}
}

func ReceiveMessage(receivedPackets <-chan common.RawBytes, messageType uint64) common.RawBytes {
	fmt.Println("Receving messages")
	for {
		buf := <-receivedPackets
		receivedType := common.Order.Uint64(buf)
		if messageType == receivedType {
			return buf
		} else {
			log.Error("We didn't receive what we were looking for!")
		}
	}

	return nil
}

type clientData struct {
	DroppedPackets uint64
	LastPacketNum  uint64
}

type server struct {
	sync.Mutex
	mgr      *resvmgr.Mgr
	sock     *snet.Conn
	sessions map[uint64]*clientData
	lastId   uint64
}

// run listens on a SCION address and replies to any ping message.
// On any error, the server exits.
func (s server) run() {
	s.sessions = make(map[uint64]*clientData)

	s.initResvMgr()
	// Listen on SCION address
	var err error
	s.sock, err = snet.ListenSCION("udp4", &local)
	if err != nil {
		LogFatal("Unable to listen", "err", err)
	}
	log.Info("Listening", "local", s.sock.LocalAddr())
	b := make(common.RawBytes, *mtu)
	sendBUffer := make(common.RawBytes, 100)
	log.Info("Starting to listen")
	for {
		_, raddr, err := s.sock.ReadFromSCION(b)
		if err != nil {
			log.Error("Unable to read", "err", err)
			// Accept failing means the socket is unusable.
			break
		}

		switch messageType := common.Order.Uint64(b); messageType {
		case TestCreate:
			log.Debug("Creating new session", "sibra_type", getSibraMode(raddr))
			newSession := MsgTestCreated{SessionId: s.lastId}
			s.sessions[s.lastId] = &clientData{
				DroppedPackets: 0,
				LastPacketNum:  0,
			}
			s.lastId++
			newSession.Pack(sendBUffer)
		case TestEnd:
			log.Debug("Sending test data back!")
			var request MsgTestEnd
			request.Unpack(b)
			response := MsgTestResult{
				SessionId:      request.SessionId,
				DroppedPackets: s.sessions[request.SessionId].DroppedPackets,
			}
			response.Pack(sendBUffer)
		case TestData:
			s.processDataRequest(b)
			continue
		default:
			log.Debug("Unknown message received", "messageType", messageType)
			continue
		}
		n, err := s.sock.WriteToSCION(sendBUffer, raddr)
		log.Debug("Wrote data to buffer", "size", n)
		if err != nil {
			log.Error("Unable to write", "err", err)
			break
		}
	}
}

func (s *server) processDataRequest(buf common.RawBytes) {
	dataPacket := MsgPayload{}
	dataPacket.Unpack(buf)
	sessId := dataPacket.SessionId
	//log.Debug("Received payload packet", "session_id", sessId)
	session := s.sessions[sessId]
	assert.Must(session != nil, "Unknown sessino ID")
	if dataPacket.PacketIndex < session.LastPacketNum {
		if session.DroppedPackets > 0 {
			session.DroppedPackets--
		}
	} else if dataPacket.PacketIndex > session.LastPacketNum {
		session.DroppedPackets += dataPacket.PacketIndex - session.LastPacketNum - 1
		session.LastPacketNum = dataPacket.PacketIndex
	}
}

func (s *server) initResvMgr() {
	saddr := local.Copy()
	saddr.L4Port = sibra.Port
	conn, err := snet.ListenSCIONWithBindSVC("udp4", saddr, nil, addr.SvcNone)
	if err != nil {
		LogFatal("Unable to listen snet", "err", err)
	}
	db, err := trustdb.New("testdb.sql")
	if err != nil {
		LogFatal("Unable to initialize trustdb", "err", err)
	}
	store, err := trust.NewStore(db, local.IA, 0, nil, log.Root())
	if err != nil {
		LogFatal("Unable to create trust store", "err", err)
	}
	s.mgr, err = resvmgr.New(snet.DefNetwork.Sciond(), conn, store, nil)
	if err != nil {
		LogFatal("Unable to start reservation manager", err)
	}
	wl4, _ := resvmgr.NetFromString(*wl4)
	wl6, _ := resvmgr.NetFromString(*wl6)
	s.mgr.AllowConnection(wl4.IA, wl4.Net)
	s.mgr.AllowConnection(wl6.IA, wl6.Net)
}

func getSibraMode(a net.Addr) string {
	saddr, ok := a.(*snet.Addr)
	if !ok {
		return "Non-sibra traffic"
	}
	_, ok = saddr.Sibra.(*sbextn.Steady)
	if ok {
		return "Steady best-effort traffic"
	}
	_, ok = saddr.Sibra.(*sbextn.Ephemeral)
	if ok {
		return "Ephemeral traffic"
	}
	return "Non-sibra traffic"

}

func (c *client) flushPath() error {
	sciondConn, err := snet.DefNetwork.Sciond().Connect()
	if err != nil {
		return err
	}
	rep, err := sciondConn.Paths(remote.IA, local.IA, 5, sd.PathReqFlags{Refresh: true})
	if err != nil {
		return common.NewBasicError("Unable to flush paths", err)
	}
	if rep.ErrorCode != sd.ErrorOk {
		return common.NewBasicError("Path flush failed", nil, "code", rep.ErrorCode)
	}
	return nil
}

func choosePath(interactive bool) *sd.PathReplyEntry {
	var paths []*sd.PathReplyEntry
	var pathIndex uint64

	pathMgr := snet.DefNetwork.PathResolver()
	pathSet := pathMgr.Query(local.IA, remote.IA)

	if len(pathSet) == 0 {
		return nil
	}
	for _, p := range pathSet {
		paths = append(paths, p.Entry)
	}
	if interactive {
		fmt.Printf("Available paths to %v\n", remote.IA)
		for i := range paths {
			fmt.Printf("[%2d] %s\n", i, paths[i].Path.String())
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("Choose path: ")
			pathIndexStr, _ := reader.ReadString('\n')
			var err error
			pathIndex, err = strconv.ParseUint(pathIndexStr[:len(pathIndexStr)-1], 10, 64)
			if err == nil && int(pathIndex) < len(paths) {
				break
			}
			fmt.Fprintf(os.Stderr, "ERROR: Invalid path index, valid indices range: [0, %v]\n", len(paths))
		}
	}
	fmt.Printf("Using path:\n  %s\n", paths[pathIndex].Path.String())
	return paths[pathIndex]
}

func (c *client) choosePathWithSibra(interactive bool, cls sibra.BwCls) (*sd.PathReplyEntry, *resvmgr.WatchState) {
	var paths []*spathmeta.AppPath
	var pathIdx uint64

	pathMgr := snet.DefNetwork.PathResolver()

	syncPaths, err := pathMgr.Watch(local.IA, remote.IA)
	if err != nil {
		return nil, nil
	}
	pathSet := syncPaths.Load().APS
	if len(pathSet) == 0 {
		return nil, nil
	}
	sibraEnabled := make([]bool, len(pathSet))
	i := 0
	wg := sync.WaitGroup{}
	wg.Add(len(pathSet))
	for k, p := range pathSet {
		paths = append(paths, p)
		kCopy := k
		iCopy := i
		go func() {
			defer wg.Done()
			ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelF()
			ws, err := c.mgr.WatchSteady(ctx, &resvmgr.PathConf{
				Paths: syncPaths,
				Key:   kCopy,
			})
			if err != nil {
				log.Debug("Unable to fetch steady reservation", "key", iCopy, "err", err)
				return
			}
			sibraEnabled[iCopy] = ws.SyncResv.Load() != nil
			c.mgr.Unwatch(ws)
		}()
		i++
	}
	wg.Wait()
	if interactive {
		fmt.Printf("Available paths to %v\n", remote.IA)
		for i := range paths {
			fmt.Printf("[%2d] %s Sibra %t\n", i, paths[i].Entry.Path.String(), sibraEnabled[i])
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("Choose path: ")
			pathIndexStr, _ := reader.ReadString('\n')
			var err error
			pathIdx, err = strconv.ParseUint(pathIndexStr[:len(pathIndexStr)-1], 10, 64)
			if err == nil && int(pathIdx) < len(paths) {
				break
			}
			fmt.Fprintf(os.Stderr, "ERROR: Invalid path index, valid indices range: [0, %v]\n", len(paths))
		}
	} else {
		var found bool
		for i, v := range sibraEnabled {
			if v {
				pathIdx = uint64(i)
				found = true
				break
			}
		}
		if !found {
			LogFatal("No SIBRA enabled path found")
		}
	}
	// Setup ephemeral reservation
	params := &resvmgr.EphemConf{
		PathConf: &resvmgr.PathConf{
			Paths: syncPaths,
			Key:   paths[pathIdx].Key(),
		},
		MaxBWCls:    cls,
		MinBWCls:    cls,
		Destination: remote.Host,
	}

	ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelF()
	log.Debug("Creating ephemeral path")
	ws, err := c.mgr.WatchEphem(ctx, params)
	if err != nil {
		LogFatal("Error reserving ephemeral reservation", "err", err)
	}
	fmt.Printf("Using path:\n  %s\n", paths[pathIdx].Entry.Path.String())
	fmt.Printf("Sibra reserved bandwidth %s ", cls.Bps())
	return paths[pathIdx].Entry, ws
}

func setSignalHandler(closer io.Closer) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		closer.Close()
		os.Exit(1)
	}()
}

type packetTiming struct {
	packetSize      int
	sleepBeforeSend time.Duration
}

func max(first, second int) int {
	if first > second {
		return first
	} else {
		return second
	}
}
func min(first, second int) int {
	return max(second, first)
}

func loadPaceFile(filename string) (packets []packetTiming, testTime time.Duration, maxPacketLength int, bwClass sibra.BwCls) {
	log.Debug("Loading file with flow information")
	csv_file, _ := os.Open(filename)
	r := csv.NewReader(csv_file)
	var totalTime time.Duration = 0
	packets = make([]packetTiming, 0)
	maxPacketLength = 0

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Error("Reading CSV file", err)
		}

		timing, _ := strconv.Atoi(record[0])
		ps, _ := strconv.Atoi(record[1])

		packets = append(packets, packetTiming{sleepBeforeSend: time.Duration(timing) * time.Microsecond, packetSize: ps})
		totalTime += time.Duration(timing) * time.Microsecond
		maxPacketLength = max(maxPacketLength, ps)
	}

	bwClass = getMaxBW(packets, 500*time.Millisecond)
	return packets, totalTime, maxPacketLength, bwClass
}

func getMaxBW(packets []packetTiming, window time.Duration) sibra.BwCls {
	var left int = 0
	var right int = 0
	log.Debug("---- calcualting requrired bandwidht")
	var currentWindow time.Duration = 0
	var currData int = 0
	var maxData int = 0
	for ; right < len(packets); right++ {
		currentWindow += packets[right].sleepBeforeSend
		currData += packets[right].packetSize

		for ; currentWindow > window && left < right; left++ {
			if currentWindow-packets[left].sleepBeforeSend < window {
				break
			}
			currentWindow -= packets[left].sleepBeforeSend
			currData -= packets[left].packetSize
		}

		maxData = max(maxData, currData)
	}

	ratio := time.Second / window
	var bps sibra.Bps = sibra.Bps(maxData * int(ratio))
	log.Debug("Calculated required bandwidth", "requiredBandwidth", bps.String(), "maxWindow", maxData)
	return bps.ToBwCls(true)
}
