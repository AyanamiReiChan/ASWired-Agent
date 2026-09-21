package tls

import (
	"github.com/xtls/xray-core/main/commands/base"
)

var CmdTLS = &base.Command{
	UsageLine: "{{.Exec}} tls",
	Short:     "TLS tools",
	Long: `{{.Exec}} {{.LongName}} provides tools for TLS.
`,
	Commands: []*base.Command{
		cmdCert,
		cmdPing,
		cmdHash,
		cmdECH,
	},
}
