// Copyright 2018 Anapaya Systems
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

package brconf

import (
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
)

var _ config.Config = (*Config)(nil)

// Config is the border router configuration that is loaded from file.
type Config struct {
	General   env.General
	Logging   env.Logging
	Metrics   env.Metrics
	Discovery Discovery
	BR        BR
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Discovery,
		&cfg.BR,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Discovery,
		&cfg.BR,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Discovery,
		&cfg.BR,
	)
}

func (cfg *Config) ConfigName() string {
	return "br_config"
}

var _ config.Config = (*BR)(nil)

// BR contains the border router specific parts of the configuration.
type BR struct {
	// Profile enables cpu and memory profiling.
	Profile bool
	// RollbackFailAction indicates the action that should be taken
	// if the rollback fails.
	RollbackFailAction FailAction
}

func (cfg *BR) InitDefaults() {
	if cfg.RollbackFailAction != FailActionContinue {
		cfg.RollbackFailAction = FailActionFatal
	}
}

func (cfg *BR) Validate() error {
	return cfg.RollbackFailAction.Validate()
}

func (cfg *BR) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, brSample)
}

func (cfg *BR) ConfigName() string {
	return "br"
}

var _ config.Config = (*Discovery)(nil)

type Discovery struct {
	idiscovery.Config
	// AllowSemiMutable indicates whether changes to the semi-mutable
	// section in the static topology are allowed.
	AllowSemiMutable bool
}

func (cfg *Discovery) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, discoverySample)
	cfg.Config.Sample(dst, path, ctx)
}

type FailAction string

const (
	// FailActionFatal indicates that the process exits on error.
	FailActionFatal FailAction = "Fatal"
	// FailActionContinue indicates that the process continues on error.
	FailActionContinue FailAction = "Continue"
)

func (f *FailAction) Validate() error {
	switch *f {
	case FailActionFatal, FailActionContinue:
		return nil
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", *f)
	}
}

func (f *FailAction) UnmarshalText(text []byte) error {
	switch FailAction(text) {
	case FailActionFatal:
		*f = FailActionFatal
	case FailActionContinue:
		*f = FailActionContinue
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", string(text))
	}
	return nil
}
