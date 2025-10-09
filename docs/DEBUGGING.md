# Debugging Melange Builds

## Readable Log Output

Melange uses structured logging by default, which can be difficult to read during interactive development. The structured output makes it hard to copy/paste commands for manual execution and can cause ANSI rendering artifacts in terminals.

### Using GCP Logging for Readable Output

A practical workaround is to use the `--gcplog` flag combined with `jq` to extract readable messages:

```bash
# Basic readable output
melange build --gcplog config.yaml 2>&1 | jq -r '.message'

# With Makefiles using MELANGE_EXTRA_ARGS
MELANGE_EXTRA_ARGS="--gcplog" make package/mypackage 2>&1 | jq -r '.message'
MELANGE_EXTRA_ARGS="--gcplog" make debug/mypackage 2>&1 | jq -r '.message'

# Filter for specific message types
melange build --gcplog config.yaml 2>&1 | jq -r 'select(.level == "info") | .message'

# Extract commands being executed
melange build --gcplog config.yaml 2>&1 | jq -r 'select(.msg | contains("running")) | .message'
```

> **Note**: This is a temporary workaround. There are plans to improve interactive logging in the future by circumventing slog for better developer experience.

### Benefits

- **Copy-pasteable commands**: Extract the exact shell commands being executed
- **Cleaner QEMU output**: More readable than structured logging artifacts  
- **No ANSI artifacts**: Avoids terminal rendering issues with charmlog
- **Filterable**: Use `jq` to focus on specific log levels or message types
- **Makefile compatible**: Works with existing Makefile workflows via `MELANGE_EXTRA_ARGS`

### Limitations

- **No color output**: ANSI colors from compilation are stripped (expected for GCP logging)
- **Requires jq**: You need `jq` installed for filtering
- **JSON overhead**: More verbose raw output before filtering
- **Temporary solution**: This workaround will be superseded by native plain-text logging

### Example Output

Instead of structured log artifacts, you get clean output like:

```
Writing Makefile for ack
Writing MYMETA.yml and MYMETA.json
+ exit 0
+ '[' -d /home/build ]
+ cd /home/build  
+ exit 1
Step failed: task exited with code 1
/bin/sh -c set -ex
[ -d '/home/build' ] || mkdir -p '/home/build'
cd '/home/build'
exit 1
```

### Advanced Filtering

For more complex debugging scenarios:

```bash
# Show timestamps with messages  
MELANGE_EXTRA_ARGS="--gcplog" make debug/package 2>&1 | jq -r '"\(.time) [\(.level)] \(.message)"'

# Extract only error messages
MELANGE_EXTRA_ARGS="--gcplog" make debug/package 2>&1 | jq -r 'select(.level == "error") | .message'

# Show pipeline steps only
MELANGE_EXTRA_ARGS="--gcplog" make debug/package 2>&1 | jq -r 'select(.msg | contains("running step")) | .message'

# Extract both message and any command fields
MELANGE_EXTRA_ARGS="--gcplog" make debug/package 2>&1 | jq -r '.message + (if .command then "\n" + .command else "" end)'

# Show QEMU-specific output
MELANGE_EXTRA_ARGS="--gcplog" make debug/package 2>&1 | jq -r 'select(.message | contains("qemu:")) | .message'
```

### Debugging Failed Steps

When a pipeline step fails, you can extract the failing command for manual execution:

```bash
# Capture the failing command
MELANGE_EXTRA_ARGS="--gcplog" make debug/package 2>&1 | jq -r 'select(.msg == "Step failed") | .message' 

# This will show both the error and the exact command that failed, making it easy to:
# 1. Copy the command for manual testing
# 2. Modify the command to debug issues  
# 3. Re-run parts of the build manually
```

### Interactive Debugging

For interactive debugging sessions, you can use:

```bash
# Get readable output while building
MELANGE_EXTRA_ARGS="--gcplog --debug-runner --interactive" make debug/package 2>&1 | jq -r '.message'
```

## Future Improvements

The structured logging issues are recognized pain points for interactive development. Future improvements may include:

- Native plain-text logging option to avoid JSON overhead
- Better command formatting for copy-paste workflows  
- Preserved ANSI color output for compilation logs
- Enhanced debugging modes with script extraction

This `--gcplog` + `jq` approach provides a practical workaround until these native improvements are available.

## Other Debugging Tips

- Use `--debug` flag to enable verbose pipeline output
- Use `--debug-runner` to keep build environment after failures
- Use `--interactive` to attach to failed builds for manual debugging