package resvd

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/sbcreate"
	"github.com/scionproto/scion/go/lib/sibra/sbreq"
	"github.com/scionproto/scion/go/lib/sibra/sbresv"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/sibra_srv/adm"
	"github.com/scionproto/scion/go/sibra_srv/conf"
	"github.com/scionproto/scion/go/sibra_srv/sbalgo/impl"
	"github.com/scionproto/scion/go/sibra_srv/sbalgo/state"
)

//TODO: (rafflc) Check this whole file

type TelescopedReserver struct {
	*BaseReserver
	baseResKey    string
	pathPredicate spathmeta.PathPredicate
}

func (r *TelescopedReserver) Run() {
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

func (r *TelescopedReserver) run() error {
	config := conf.Get()
	resMaster := conf.Get().RepMaster

	res, ok := config.Reservations.GetReservation(r.resvKey)
	if !ok {
		//TODO: Cleanup this telescope!
		return common.NewBasicError("Reservation not found", nil)
	}

	basePath, err := resMaster.GetReservationsPath(r.baseResKey)
	if err != nil {
		return err
	}
	if basePath == nil {
		r.Logger.Warn("Base reservation doesn't have a path!")
		return nil
	}
	baseId, err := resMaster.GetReservationId(r.baseResKey)
	if err != nil {
		return err
	}
	if baseId == nil {
		r.Logger.Warn("Base reservation doesn't have a ID!")
		return nil
	}

	if !r.preparePath(config, res, basePath) {
		return nil
	}

	var e *state.SteadyResvEntry
	switch algo := config.SibraAlgo.(type) {
	case *impl.AlgoFast:
		e, ok = algo.SteadyMap.Get(r.resvID)
	case *impl.AlgoSlow:
		e, ok = algo.SteadyMap.Get(r.resvID)
	}
	if !ok || e.Expired(time.Now()) {
		r.setupResv(config, res, baseId)
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

func (r *TelescopedReserver) setupResv(config *conf.Conf, res *conf.Resv, baseId sibra.ID) {
	resDetails := r.controller.SetupReservation(config)

	s := &SteadyTelescopeSetup{
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
		path:   r.path,
		pt:     resDetails.PathType,
		baseId: baseId,
		ephMetric: prometheus.Labels{
			"dstAs": res.IA.String(),
			"type":  res.PathType.String()},
	}
	go s.Run(s)
}

func (r *TelescopedReserver) preparePath(config *conf.Conf, res *conf.Resv, basePath *spathmeta.AppPath) bool {
	assert.Must(basePath != nil, "Base path must exist!")

	pathPred := spathmeta.PathPredicate{
		Match: basePath.Entry.Path.Interfaces,
	}

	if !r.checkPath(config, &pathPred) {
		if err := r.setSyncPaths(config, &pathPred, res.IA); err != nil {
			r.Debug("Unable to set sync path", "err", err)
			return false
		}
		if !r.checkPath(config, &pathPred) {
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
	r.path = path
	return true
}

type SteadyTelescopeSetup struct {
	*ResvReqstr
	path      *spathmeta.AppPath
	pt        sibra.PathType
	baseId    sibra.ID
	ephMetric prometheus.Labels
}

func (s *SteadyTelescopeSetup) probeRLC() (sibra.RLC, error) {
	rlc := sibra.DurationToRLC(500*time.Millisecond, false)
	s.timeout = rlc.Duration()
	return rlc, nil
}

func (s *SteadyTelescopeSetup) CreateExtPkt() (*conf.ExtPkt, error) {
	var err error
	pkt := &conf.ExtPkt{
		Conf: conf.Get(),
	}
	pLen := uint8((len(s.path.Entry.Path.Interfaces) + 2) / 2)
	rlc, err := s.probeRLC()
	if err != nil {
		return nil, common.NewBasicError("Unable to probe rlc", err)
	}
	info := &sbresv.Info{
		ExpTick:  sibra.CurrentTick() + sibra.MaxSteadyTicks,
		BwCls:    s.max,
		RLC:      rlc,
		PathType: s.pt,
		Index:    s.idx,
	}
	s.Debug("Creating steady telescoped request", "baseId", s.baseId)
	pkt.Pld = steadyTelescopeReq(s.baseId, info, s.min, s.max, s.props, s.split, int(pLen))
	pkt.Steady, err = sbcreate.NewSteadySetup(pkt.Pld.Data.(*sbreq.SteadyReq), s.id)
	if err != nil {
		return nil, err
	}
	sPath := spath.New(s.path.Entry.Path.FwdPath)
	if err := sPath.InitOffsets(); err != nil {
		return nil, err
	}

	pkt.Spkt = &spkt.ScnPkt{
		DstIA:   s.path.Entry.Path.DstIA(),
		SrcIA:   s.path.Entry.Path.SrcIA(),
		DstHost: s.dstHost,
		SrcHost: s.srcHost,
		Path:    sPath,
		HBHExt:  []common.Extension{pkt.Steady},
		L4:      l4.L4Header(&l4.UDP{Checksum: make(common.RawBytes, 2)}),
	}
	return pkt, nil
}

func (s *SteadyTelescopeSetup) PrepareReq(pkt *conf.ExtPkt) error {
	resvReq := pkt.Pld.Data.(*sbreq.SteadyReq)

	if err := adm.AdmitSteadyResv(pkt, resvReq, s.ephMetric); err != nil {
		return common.NewBasicError("Unable to admit reservation", err)
	}
	if !pkt.Pld.Accepted {
		return common.NewBasicError("Not enough bandwidth", nil)
	}
	if err := pkt.Steady.NextSOFIndex(); err != nil {
		return err
	}
	return nil
}

func (s *SteadyTelescopeSetup) NotifyKey() []*conf.NotifyKey {
	return []*conf.NotifyKey{{Id: s.id, Idx: s.idx, ReqType: sbreq.RSteadySetupTelescope}}
}

func (s *SteadyTelescopeSetup) HandleRep(pkt *conf.ExtPkt) error {
	if err := s.handleRep(pkt); err != nil {
		return err
	}
	block := pkt.Pld.Data.(*sbreq.SteadySucc).Block
	c := &ConfirmIndex{
		Reqstr: &Reqstr{
			Logger:  s.Logger.New("sub", "ConfirmIndex", "state", sibra.StatePending),
			id:      s.id,
			idx:     s.idx,
			resvKey: s.resvKey,
			stop:    s.stop,
			path:    s.path,
			srcHost: s.srcHost,
			dstHost: pkt.Spkt.SrcHost,
			block:   block,
			timeout: block.Info.RLC.Duration(),
		},
		state: sibra.StatePending,
	}
	go c.Run(c)
	return nil
}

// TODO: (rafflc) Deal with TimeStamp

func steadyTelescopeReq(baseId sibra.ID, info *sbresv.Info, min, max sibra.BwCls, props sibra.EndProps,
	split sibra.SplitCls, numHops int) *sbreq.Pld {

	// Create request block.
	req := &sbreq.SteadyReq{
		BaseID:      baseId,
		DataType:    sbreq.RSteadySetupTelescope,
		AccBw:       max,
		EndProps:    props,
		Split:       split,
		Info:        info,
		MinBw:       min,
		MaxBw:       max,
		OfferFields: make([]*sbreq.Offer, numHops),
	}
	// Initialize the offer fields.
	for i := range req.OfferFields {
		req.OfferFields[i] = &sbreq.Offer{}
	}
	// Set allocated bandwidth in own offer field.
	if req.Info.PathType.Reversed() {
		req.OfferFields[len(req.OfferFields)-1].AllocBw = max
	} else {
		req.OfferFields[0].AllocBw = max
	}
	pld := &sbreq.Pld{
		NumHops:  uint8(numHops),
		Type:     sbreq.RSteadySetupTelescope,
		Data:     req,
		Accepted: true,
		Auths:    make([]common.RawBytes, numHops),
		//TimeStamp: uint32(time.Now().Unix()),
	}
	pld.TotalLen = uint16(pld.Len())
	return pld
}
