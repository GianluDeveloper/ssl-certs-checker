package config

type Config struct {
	Hosts []string `yaml:"hosts"`
}

type AppConfig struct {
	ConfigFile       string
	Domains          string
	DomainsFile      string
	DomainsFileSkip  int
	DomainsFileLimit int
	Timeout          int
	Insecure         bool
	OutputFormat     string
	OutputFile       string
}
