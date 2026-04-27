package cmd

import (
	"fmt"

	"github.com/sikalabs/sikalabs-kubernetes-oidc-login/pkg/login"
	"github.com/sikalabs/sikalabs-kubernetes-oidc-login/version"
	"github.com/spf13/cobra"
)

var FlagIssuer string
var FlagClientID string
var FlagClientSecret string

type GetCmdOpts struct {
	NameOverride string
}

func GetCmd(opts ...GetCmdOpts) *cobra.Command {
	var name string = "sikalabs-kubernetes-oidc-login"
	if len(opts) > 0 && opts[0].NameOverride != "" {
		name = opts[0].NameOverride
	}

	var Cmd = &cobra.Command{
		Use:          name,
		Short:        "Perform OIDC login and output Kubernetes ExecCredential for kubectl",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return login.Login(FlagIssuer, FlagClientID, FlagClientSecret)
		},
	}
	Cmd.Flags().StringVar(&FlagIssuer, "oidc-issuer-url", "", "OIDC Issuer URL")
	Cmd.MarkFlagRequired("oidc-issuer-url")
	Cmd.Flags().StringVar(&FlagClientID, "oidc-client-id", "", "OIDC Client ID")
	Cmd.MarkFlagRequired("oidc-client-id")
	Cmd.Flags().StringVar(&FlagClientSecret, "oidc-client-secret", "", "OIDC Client Secret")

	var VersionCmd = &cobra.Command{
		Use:     "version",
		Short:   "Prints version",
		Aliases: []string{"v"},
		Args:    cobra.NoArgs,
		Run: func(c *cobra.Command, args []string) {
			fmt.Printf("%s\n", version.Version)
		},
	}
	Cmd.AddCommand(VersionCmd)
	return Cmd
}
