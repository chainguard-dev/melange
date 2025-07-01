---
title: "melange completion"
slug: melange_completion
url: /docs/md/melange_completion.md
draft: false
images: []
type: "article"
toc: true
---
## melange completion

Generate completion script

### Synopsis

To load completions:
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


```
melange completion [bash|zsh|fish|powershell]
```

### Options

```
  -h, --help   help for completion
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

