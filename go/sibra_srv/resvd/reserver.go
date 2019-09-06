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

package resvd

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/go/sibra_srv/resvd/controller"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sibra_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/resvdb/query"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/sibra_srv/conf"
	"github.com/scionproto/scion/go/sibra_srv/sbalgo/impl"
	"github.com/scionproto/scion/go/sibra_srv/sbalgo/state"
)

// FIXME(roosd): teardown paths which are no longer used

var idSuffix uint32
var idSuffixLock sync.Mutex

func getID(config *conf.Conf) sibra.ID {
	idSuffixLock.Lock()
	defer idSuffixLock.Unlock()
	id := sibra.NewSteadyID(config.PublicAddr.IA.A, idSuffix)
	idSuffix++
	return id
}

type BaseReserver struct {
	sync.Mutex
	log.Logger
	resvKey    string
	resvID     sibra.ID
	syncPaths  *pathmgr.SyncPaths
	filter     *pktcls.ActionFilterPaths
	pred       string
	pathKey    spathmeta.PathKey
	pathLock   sync.RWMutex
	path       *spathmeta.AppPath
	notifyReg  chan NotifyReg
	stop       chan struct{}
	stopped    bool
	controller controller.ReservationController
}

func (r *BaseReserver) Run() {
	for {
		select {
		case <-r.stop:
			r.Info("Reserver stopped")
			return
		default:
			if err := r.run(); err != nil {
				goto Stop
			}
			time.Sleep(1 * time.Second)
		}
	}
	return
Stop:
	r.Lock()
	r.stopped = true
	r.Unlock()
	r.Warn("Reserver broke out of infinite loop")
}

func (r *BaseReserver) run() error {
	config := conf.Get()
	res, exists := config.Reservations.GetReservation(r.resvKey)
	if !exists {
		//TODO: Reservation has been deleted, initialize cleanup procedure
		return common.NewBasicError("Reservation not found", nil)
	}
	if !r.preparePath(config, res) {
		return nil
	}
	var e *state.SteadyResvEntry
	var ok bool
	switch algo := config.SibraAlgo.(type) {
	case *impl.AlgoFast:
		e, ok = algo.SteadyMap.Get(r.resvID)
	case *impl.AlgoSlow:
		e, ok = algo.SteadyMap.Get(r.resvID)
	}
	if !ok || e.Expired(time.Now()) {
		r.setupResv(config, res)
		return nil
	}
	if r.isRecent(config, e) {
		return nil
	}
	if r.tempExists(config, e) {
		return nil
	}
	if r.switchIndex(config, e) {
		return nil
	}
	if err := r.renewResv(config, e, res); err != nil {
		r.Error("Unable to renew", "err", err)
	}
	return nil
}

func (r *BaseReserver) isRecent(config *conf.Conf, e *state.SteadyResvEntry) bool {
	e.RLock()
	defer e.RUnlock()
	idx := e.Indexes[e.ActiveIndex]
	if idx == nil || idx.State != sibra.StateActive {
		return false
	}
	if time.Until(idx.Info.ExpTick.Time()) < 5*sibra.TickDuration {
		return false
	}
	return !r.controller.ShouldRenew(controller.ReservationDetails{
		Min:   idx.MinBW,
		Max:   idx.MaxBW,
		Props: idx.EndProps,
		Split: idx.Split,
	})
}

func (r *BaseReserver) tempExists(config *conf.Conf, e *state.SteadyResvEntry) bool {
	e.RLock()
	defer e.RUnlock()
	for _, idx := range e.Indexes {
		if idx != nil && idx.State == sibra.StateTemp {
			return true
		}
	}
	return false
}

func (r *BaseReserver) switchIndex(config *conf.Conf, e *state.SteadyResvEntry) bool {
	e.Lock()
	defer e.Unlock()
	idx := e.Indexes[e.ActiveIndex]
	if idx != nil {
		loc := config.LocalResvs.Get(r.resvID, e.ActiveIndex)
		failed := loc != nil && loc.State == sibra.StatePending && idx.State == sibra.StateActive
		// Activate initial index and failed attempts
		if idx.State == sibra.StatePending || failed {
			log.Debug("Using default activate index...")
			r.activateIdx(config, e.ActiveIndex)
			return true
		}
	}
	now := time.Now()
	pending := make([]*state.SteadyResvIdx, 0, 16)
	for _, i := range e.Indexes {
		if i == nil {
			continue
		}
		if i.Active(now) && i.State == sibra.StatePending {
			pending = append(pending, i)
		}
	}
	if len(pending) < 1 {
		return false
	}
	nextIndex := r.controller.ChooseIndex(pending)
	log.Debug("Switching index!", "fromBw", idx.Info.BwCls, "toBw", nextIndex.Info.BwCls)
	r.activateIdx(config, nextIndex.Info.Index)
	return true
}

func (r *BaseReserver) activateIdx(config *conf.Conf, idx sibra.Index) {
	r.pathLock.RLock()
	defer r.pathLock.RUnlock()

	r.Debug("Starting to activate index", "idx", idx)
	//IDEA: (rafflc) Make sure this steady block here has type reservation
	e := config.LocalResvs.Get(r.resvID, idx)

	// FIXME(roosd): set correct signature and whitelist
	meta := &sibra_mgmt.BlockMeta{
		Id:          r.resvID,
		RawCreation: uint32(e.Creation.Unix()),
		Signature:   make(common.RawBytes, 1),
		WhiteList:   make(common.RawBytes, 1),
		Mtu:         r.path.Entry.Path.Mtu,
	}
	meta.SetBlock(e.Block)
	meta.SetInterfaces(r.pathToIntfs(r.path, e.Block.Info.PathType))
	c := &ConfirmIndex{
		Reqstr: &Reqstr{
			Logger: r.Logger.New("reqstr", "ConfirmIndex", "state", sibra.StateActive,
				"id", r.resvID, "idx", idx),
			id:      r.resvID,
			idx:     idx,
			resvKey: r.resvKey,
			stop:    r.stop,
			path:    r.path,
			srcHost: config.PublicAddr.Host,
			dstHost: addr.SvcSB,
			block:   e.Block,
			timeout: e.Block.Info.RLC.Duration(),

			succFunc: func(ReqstrI) {
				//TODO (rafflc) This is the only place where steady meta reservations are stored
				// make sure they are in reservation state here :)
				r.Info("insert", "s", meta.StartIA(), "e", meta.EndIA())
				if _, err := conf.Get().ResvDB.Insert(meta); err != nil {
					r.Debug("Unable to insert", "err", err)
					return
				}
				r.controller.ReservationConfirmed(meta.Block)
			},
		},
		state: sibra.StateActive,
	}
	go c.Run(c)
}

func (r *BaseReserver) setupResv(config *conf.Conf, res *conf.Resv) {
	resDetails := r.controller.SetupReservation(config)

	r.pathLock.RLock()
	defer r.pathLock.RUnlock()

	s := &SteadySetup{
		ResvReqstr: &ResvReqstr{
			Reqstr: &Reqstr{
				Logger:  r.Logger.New("reqstr", "SteadySetup", "id", r.resvID, "idx", 0),
				id:      r.resvID,
				resvKey: r.resvKey,
				stop:    r.stop,
				path:    r.path,
				srcHost: config.PublicAddr.Host,
				dstHost: addr.SvcSB,
			},
			min:   resDetails.Min,
			max:   resDetails.Max,
			split: resDetails.Split,
			props: resDetails.Props,
		},
		path: r.path,
		pt:   resDetails.PathType,
		ephMetric: prometheus.Labels{
			"dstAs": res.IA.String(),
			"type":  res.PathType.String()},
	}
	go s.Run(s)
}

func (r *BaseReserver) renewResv(config *conf.Conf, e *state.SteadyResvEntry, res *conf.Resv) error {
	resDetails := r.controller.RenewReservation(config)

	r.pathLock.RLock()
	defer r.pathLock.RUnlock()

	p := &query.Params{
		ResvID: r.resvID,
		SegID:  sibra_mgmt.PathToSegID(r.pathToIntfs(r.path, resDetails.PathType)),
	}
	// IDEA: (rafflc) ResvDB.Get returns meta blocks of steady reservations
	// the SOF should have type Reservation
	results, err := config.ResvDB.Get(p)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return common.NewBasicError("Invalid number of results", nil, "len", len(results))
	}
	idx, err := r.findFreeIdx(e)
	if err != nil {
		return err
	}
	r.Debug("Starting renew request", "idx", idx)
	s := &SteadyRenew{
		ResvReqstr: &ResvReqstr{
			Reqstr: &Reqstr{
				Logger:  r.Logger.New("reqstr", "SteadyRenew", "id", r.resvID, "idx", idx),
				id:      r.resvID,
				idx:     idx,
				resvKey: r.resvKey,
				stop:    r.stop,
				path:    r.path,
				srcHost: config.PublicAddr.Host,
				dstHost: addr.SvcSB,
				block:   results[0].BlockMeta.Block,
				timeout: results[0].BlockMeta.Block.Info.RLC.Duration(),
			},
			min:   resDetails.Min,
			max:   resDetails.Max,
			split: resDetails.Split,
			props: resDetails.Props,
		},
		ephMetric: prometheus.Labels{
			"dstAs": res.IA.String(),
			"type":  res.PathType.String()},
	}
	go s.Run(s)
	return nil
}

func (r *BaseReserver) findFreeIdx(e *state.SteadyResvEntry) (sibra.Index, error) {
	e.RLock()
	defer e.RUnlock()
	start := (e.ActiveIndex + 1) % sibra.NumIndexes
	for i := start; i != e.ActiveIndex; i = (i + 1) % sibra.NumIndexes {
		if e.Indexes[i] == nil {
			return i, nil
		}
	}
	return 0, common.NewBasicError("All indexes occupied", nil)
}

func (r *BaseReserver) preparePath(config *conf.Conf, res *conf.Resv) bool {
	if !r.checkPath(config, res.PathPredicate) {
		if err := r.setSyncPaths(config, res.PathPredicate, res.IA); err != nil {
			r.Debug("Unable to set sync path", "err", err)
			return false
		}
		if !r.checkPath(config, res.PathPredicate) {
			r.Debug("No path found")
			return false
		}
	}
	path, n := r.getPath(config)
	if path == nil {
		r.Debug("Unable to get path")
		return false
	}
	if n {
		r.pathKey = path.Key()
		r.resvID = getID(config)
	}

	r.pathLock.Lock()
	defer r.pathLock.Unlock()
	r.path = path
	return true
}

func (r *BaseReserver) checkPath(config *conf.Conf, pathPred *spathmeta.PathPredicate) bool {
	if r.syncPaths == nil || r.syncPaths.Load().APS.GetAppPath(r.pathKey) == nil {
		return false
	}
	if r.pred != pathPred.String() {
		return false
	}
	return true
}

func (r *BaseReserver) setSyncPaths(config *conf.Conf, pathPred *spathmeta.PathPredicate, dst addr.IA) error {
	var err error
	r.pathKey = ""
	pathRes := snet.DefNetwork.PathResolver()
	if r.pred != pathPred.String() {
		r.pred = pathPred.String()
		r.filter = pktcls.NewActionFilterPaths(
			r.resvKey, pktcls.NewCondPathPredicate(pathPred))
		r.syncPaths, err = pathRes.WatchFilter(config.PublicAddr.IA, dst, r.filter)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *BaseReserver) getPath(config *conf.Conf) (*spathmeta.AppPath, bool) {
	path := r.syncPaths.Load().APS.GetAppPath(r.pathKey)
	if path == nil {
		return nil, true
	}
	if path.Key() != r.pathKey {
		return path, true
	}
	return path, false
}

func (r *BaseReserver) pathToIntfs(path *spathmeta.AppPath,
	pathType sibra.PathType) []sibra_mgmt.PathInterface {

	intfs := make([]sibra_mgmt.PathInterface, len(r.path.Entry.Path.Interfaces))
	for i := range r.path.Entry.Path.Interfaces {
		intfs[i].IfID = r.path.Entry.Path.Interfaces[i].IfID
		intfs[i].RawIsdas = r.path.Entry.Path.Interfaces[i].RawIsdas
	}
	if pathType.Reversed() {
		for i, j := 0, len(intfs)-1; i < j; i, j = i+1, j-1 {
			intfs[i], intfs[j] = intfs[j], intfs[i]
		}
	}
	return intfs
}

func (r *BaseReserver) GetReservationPath() *spathmeta.AppPath {
	r.pathLock.RLock()
	defer r.pathLock.RUnlock()
	return r.path
}

func (r *BaseReserver) GetReservationID() sibra.ID {
	return r.resvID
}

func (r *BaseReserver) Close() {
	r.Lock()
	defer r.Unlock()
	if !r.stopped {
		close(r.stop)
		r.stopped = true
	}
}

func (r *BaseReserver) Closed() bool {
	r.Lock()
	defer r.Unlock()
	return r.stopped
}
