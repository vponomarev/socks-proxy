package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Strategy struct {
	Name        string            `yaml:"name"`
	List        string            `yaml:"list"`
	Action      string            `yaml:"action"`
	Params      map[string]string `yaml:"params"`
	ListRecords []DomainRecord    `yaml:"-"`
}

type Proxy struct {
	Address string
	Port    int `yaml:"port"`
}

type FakeSni struct {
	Interface string `yaml:"interface"`
	Ttl       int    `yaml:"ttl"`
}

type Config struct {
	Proxy    Proxy
	FakeSni  FakeSni `yaml:"fake-sni"`
	Strategy []Strategy
}

func LoadConfig(path string) (config *Config, err error) {
	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Create a new Config instance
	config = &Config{}

	// Unmarshal the YAML data into the config struct
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	// Load all lists
	for i := range config.Strategy {
		if config.Strategy[i].List != "" {
			dl := DomainList{}
			err = dl.Load(config.Strategy[i].List)
			if err != nil {
				return nil, fmt.Errorf("strategy '%s' - error loading list '%s': %v", config.Strategy[i].Name, config.Strategy[i].List, err)
			}
			config.Strategy[i].ListRecords = dl.Records
		}
	}

	return config, nil

}

func (c *Config) IsFakeStrategy(targetHost string) (ok bool, replace string) {
	replace = targetHost

	for _, cr := range c.Strategy {
		if cr.Action != "fake-sni" {
			continue
		}
		for _, rec := range cr.ListRecords {
			if rec.Regexp != nil {
				if rec.Regexp.MatchString(targetHost) {
					ok = true
					replace = replace[:len(replace)-1] + "x"
					return
				}
			}
		}
	}

	return false, replace
}
