// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func completion() *cobra.Command {
	completionCmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:
Bash:

$ source <(melange completion bash)

# To load completions for each session, execute once:
Linux:
  $ melange completion bash > /etc/bash_completion.d/yourprogram
MacOS:
  $ melange completion bash > /usr/local/etc/bash_completion.d/yourprogram

Zsh:

# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

# To load completions for each session, execute once:
$ melange completion zsh > "${fpath[1]}/_melange"

# You will need to start a new shell for this setup to take effect.

Fish:

$ melange completion fish | source

# To load completions for each session, execute once:
$ melange completion fish > ~/.config/fish/completions/melange.fish
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				// Print an error message and exit if no argument is provided
				log.Fatal("A shell type (bash, zsh, fish, powershell) is required.")
			}

			switch args[0] {
			case "bash":
				err := cmd.Root().GenBashCompletion(os.Stdout)
				if err != nil {
					log.Fatalf("Error generating Bash completion script: %v", err)
				}
			case "zsh":
				err := cmd.Root().GenZshCompletion(os.Stdout)
				if err != nil {
					log.Fatalf("Error generating Zsh completion script: %v", err)
				}
			case "fish":
				err := cmd.Root().GenFishCompletion(os.Stdout, true)
				if err != nil {
					log.Fatalf("Error generating fish completion script: %v", err)
				}
			case "powershell":
				err := cmd.Root().GenPowerShellCompletion(os.Stdout)
				if err != nil {
					log.Fatalf("Error generating PowerShell completion script: %v", err)
				}
			default:
				log.Fatalf("A shell type (bash, zsh, fish, powershell) is required.")
			}
		},
	}
	return completionCmd
}
