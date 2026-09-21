package base

type CommandEnvHolder struct {
	Exec string

	CommandsWidth int
}

var CommandEnv CommandEnvHolder

func init() {

	CommandEnv.Exec = "xray"
}
