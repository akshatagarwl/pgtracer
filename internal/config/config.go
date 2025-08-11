package config

import (
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	UsePerfBuf      bool          `env:"PGTRACER_USE_PERFBUF" envDefault:"false"`
	ProcFSPath      string        `env:"PGTRACER_PROCFS_PATH" envDefault:"/proc"`
	CleanupInterval time.Duration `env:"PGTRACER_CLEANUP_INTERVAL" envDefault:"5m"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
