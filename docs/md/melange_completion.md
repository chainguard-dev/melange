---
title: "melange completion"
slug: melange_completion
url: /open-source/melange/reference/melange_completion/
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

### SEE ALSO

* [melange](/open-source/melange/reference/melange/)	 - 

