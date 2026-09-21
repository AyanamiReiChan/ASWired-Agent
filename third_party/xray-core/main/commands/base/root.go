package base

var RootCommand *Command

func init() {
	RootCommand = &Command{
		UsageLine: CommandEnv.Exec,
		Long:      "The root command",
	}
}

func RegisterCommand(cmd *Command) {
	RootCommand.Commands = append(RootCommand.Commands, cmd)
}
