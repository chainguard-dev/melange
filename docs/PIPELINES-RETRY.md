# Pipeline Retry Configuration

## Overview

Melange supports automatic retry functionality for pipelines to improve build robustness against transient failures. When a pipeline fails, it can automatically retry from the beginning using configurable backoff strategies.

## When to Use Retry

Retry functionality is particularly useful for:

- **Network operations**: Fetching remote resources that may experience temporary connectivity issues
- **Flaky tests**: Tests that occasionally fail due to timing issues or external dependencies
- **Resource contention**: Operations that may fail due to temporary resource unavailability
- **External service dependencies**: Calls to external APIs or services that may be temporarily unavailable

## Configuration

Add a `retry` block to any pipeline to enable retry functionality:

```yaml
pipeline:
  - name: my-pipeline
    retry:
      attempts: 3
      backoff: exponential
      initial-delay: 1s
      max-delay: 60s
    runs: ./some-command
```

### Configuration Options

#### `attempts` (integer, default: 1)

The number of times to attempt the pipeline execution. Must be at least 1.

- If set to 1, the pipeline runs once without retries (default behavior)
- Higher values increase resilience but may extend build time
- Values over 10 will generate a warning

**Example:**
```yaml
retry:
  attempts: 5  # Try up to 5 times total
```

#### `backoff` (string, default: "exponential")

The backoff strategy to use between retry attempts. Valid values:

- **`exponential`** (default): Delay doubles with each retry (1s, 2s, 4s, 8s, ...)
- **`linear`**: Delay increases by a fixed amount (1s, 2s, 3s, 4s, ...)
- **`constant`**: Same delay between all retries (1s, 1s, 1s, 1s, ...)

**Recommendations:**
- Use `exponential` for network operations and external services (gives systems time to recover)
- Use `linear` for resource contention issues
- Use `constant` for simple retry scenarios with predictable failure modes

**Example:**
```yaml
retry:
  attempts: 4
  backoff: linear
```

#### `initial-delay` (duration string, default: "1s")

The initial delay before the first retry attempt. Accepts duration strings like:
- `500ms` - milliseconds
- `1s` - seconds
- `2m` - minutes
- `1h30m` - combined units

For exponential and linear backoff, this value is the base delay that gets multiplied.

**Example:**
```yaml
retry:
  attempts: 3
  initial-delay: 2s  # Wait 2 seconds before first retry
```

#### `max-delay` (duration string, default: "60s")

The maximum delay between retry attempts. Prevents exponential backoff from growing too large.

**Example:**
```yaml
retry:
  attempts: 10
  backoff: exponential
  initial-delay: 1s
  max-delay: 30s  # Cap delays at 30 seconds
```

## Behavior

### Retry Logic

1. Pipeline executes normally on the first attempt
2. If the pipeline fails:
   - Log the failure with attempt number
   - Calculate backoff delay based on strategy
   - Wait for the calculated delay (respecting context cancellation)
   - Retry the pipeline from the beginning
3. Repeat until:
   - Pipeline succeeds (returns success)
   - Maximum attempts reached (returns final error)
   - Context is cancelled, e.g., via Ctrl+C (returns cancellation error)

### State Between Retries

**Important**: Retries do not perform any automatic cleanup. The entire pipeline re-runs from the beginning in the same environment. This means:

- Files created by previous attempts remain
- Environment variables persist
- The working directory is not reset

### Idempotency Considerations

For retry to work correctly, pipelines should be designed to be **idempotent** - running them multiple times should have the same effect as running once.

**Good practices:**
```yaml
# Use -f flag to make commands idempotent
runs: mkdir -p /tmp/build  # creates or uses existing directory

# Check for existing state
runs: |
  if [ ! -f config.done ]; then
    ./configure
    touch config.done
  fi

# Clean up before retrying
runs: |
  rm -rf build/
  make clean
  make build
```

**Avoid:**
```yaml
# This will fail on retry if directory exists
runs: mkdir /tmp/build

# This might produce unexpected results on retry
runs: echo "line" >> logfile.txt
```

## Backoff Strategies Explained

### Exponential Backoff (Default)

Delay = 2^(attempt_number) × initial-delay, capped at max-delay

**Example** with `initial-delay: 1s`, `max-delay: 60s`:
- Attempt 1 → fails → wait 1s
- Attempt 2 → fails → wait 2s
- Attempt 3 → fails → wait 4s
- Attempt 4 → fails → wait 8s
- Attempt 5 → fails → wait 16s

**Best for**: Network operations, external services, scenarios where systems need time to recover.

### Linear Backoff

Delay = (attempt_number + 1) × initial-delay, capped at max-delay

**Example** with `initial-delay: 1s`, `max-delay: 60s`:
- Attempt 1 → fails → wait 1s
- Attempt 2 → fails → wait 2s
- Attempt 3 → fails → wait 3s
- Attempt 4 → fails → wait 4s
- Attempt 5 → fails → wait 5s

**Best for**: Resource contention, database operations, moderate backpressure scenarios.

### Constant Backoff

Delay = initial-delay (max-delay is ignored)

**Example** with `initial-delay: 5s`:
- Attempt 1 → fails → wait 5s
- Attempt 2 → fails → wait 5s
- Attempt 3 → fails → wait 5s
- Attempt 4 → fails → wait 5s

**Best for**: Simple polling scenarios, known recovery times, flaky operations with predictable timing.

## Usage Examples

### Example 1: Retry Network Fetch

```yaml
pipeline:
  - name: fetch-source
    retry:
      attempts: 5
      backoff: exponential
      initial-delay: 2s
      max-delay: 30s
    uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...
```

### Example 2: Retry Flaky Tests

```yaml
pipeline:
  - name: integration-tests
    retry:
      attempts: 3
    runs: make integration-test
```

### Example 3: Retry Multiple Steps Together

```yaml
pipeline:
  - name: build-and-test
    retry:
      attempts: 3
      backoff: exponential
    pipeline:
      - runs: ./configure
      - runs: make
      - runs: make test
```

If any step fails, all steps retry from the beginning.

### Example 4: Different Retry Strategies

```yaml
pipeline:
  # Quick retries for flaky network
  - name: download-deps
    retry:
      attempts: 5
      backoff: exponential
      initial-delay: 1s
      max-delay: 60s
    runs: go mod download

  # Slower retries for external API
  - name: notify-service
    retry:
      attempts: 3
      backoff: constant
      initial-delay: 10s
    runs: curl -X POST https://api.example.com/notify
```

## Nested Pipelines

Each pipeline level handles its own retry configuration independently:

```yaml
pipeline:
  - name: outer-pipeline
    retry:
      attempts: 2
    pipeline:
      - name: inner-pipeline-1
        retry:
          attempts: 3
        runs: ./command1

      - name: inner-pipeline-2
        runs: ./command2
```

In this example:
- `inner-pipeline-1` can retry up to 3 times
- `inner-pipeline-2` has no retry (runs once)
- If `inner-pipeline-1` exhausts its retries and still fails, `outer-pipeline` will retry both inner pipelines

## Interactive Debug Mode

When using melange's interactive debug mode (`--interactive-mode`):
- The debug prompt only appears on the **final** failure, not on intermediate retry attempts
- This prevents interrupting the automatic retry flow
- If all retries are exhausted, you can debug the final failure state

## Context Cancellation

Retry loops respect context cancellation:
- Pressing Ctrl+C will immediately stop the retry loop
- The current pipeline execution completes, then the retry loop exits
- Delays between retries are interruptible

## Performance Considerations

### Build Time Impact

Retries increase build time on failure:
- 3 attempts with exponential backoff (1s initial): ~7s additional time if all fail
- 5 attempts with linear backoff (2s initial): ~30s additional time if all fail
- 10 attempts with exponential backoff (1s initial, 30s max): ~4-5 minutes if all fail

**Recommendations:**
- Use retry for operations with high success rates but occasional failures
- Avoid retry for operations that consistently fail (fix the underlying issue instead)
- Set appropriate `max-delay` to prevent excessive wait times
- Consider using fewer attempts with longer delays for external services

### Log Verbosity

Retry attempts generate additional log output:
- Each failure logs at WARN level with attempt count
- Each retry logs at INFO level with delay time
- Final failure includes total attempt count

## Validation Errors

The following errors are caught during pipeline compilation:

- **Invalid attempts**: Must be at least 1
- **Invalid backoff**: Must be "constant", "linear", or "exponential"
- **Invalid duration**: `initial-delay` and `max-delay` must be valid duration strings
- **Warning for high attempts**: Values over 10 generate a warning (not an error)

**Example error:**
```
Error: invalid retry configuration: backoff must be one of [constant linear exponential], got "custom"
```

## Best Practices

1. **Design for idempotency**: Ensure your pipelines can be safely re-run
2. **Use appropriate backoff**: Match the backoff strategy to the failure mode
3. **Set reasonable attempts**: 3-5 attempts is usually sufficient
4. **Cap max-delay**: Prevent exponential backoff from causing excessive delays
5. **Log meaningful messages**: Help diagnose issues when retries are triggered
6. **Test retry behavior**: Verify your pipelines handle retries correctly
7. **Don't mask real issues**: Use retry for transient failures, not persistent bugs

## Common Use Cases

### Flaky Network Operations

```yaml
- name: fetch-dependencies
  retry:
    attempts: 5
    backoff: exponential
    initial-delay: 1s
    max-delay: 30s
  runs: |
    curl --fail --max-time 30 https://cdn.example.com/deps.tar.gz
    tar xf deps.tar.gz
```

### Flaky Test Suite

```yaml
- name: run-e2e-tests
  retry:
    attempts: 3
    backoff: linear
    initial-delay: 5s
  runs: |
    # Clean up any leftover test state
    ./cleanup-test-env.sh
    # Run tests
    npm run test:e2e
```

### External Service Dependencies

```yaml
- name: verify-signature
  retry:
    attempts: 4
    backoff: exponential
    initial-delay: 2s
    max-delay: 60s
  runs: |
    cosign verify --key cosign.pub image:tag
```

## Troubleshooting

### Pipeline keeps retrying but never succeeds

**Problem**: All retry attempts fail.

**Solutions**:
- Check if the underlying issue is transient or persistent
- Review logs to identify the root cause
- Ensure the pipeline is idempotent
- Consider if retry is appropriate for this failure mode

### Retries take too long

**Problem**: Exponential backoff causes long delays.

**Solutions**:
- Reduce `max-delay` to cap the maximum wait time
- Use linear or constant backoff instead
- Reduce the number of `attempts`

### Pipeline succeeds locally but fails with retry

**Problem**: Retry logic causes unexpected behavior.

**Solutions**:
- Check for state pollution between attempts (files, environment variables)
- Add cleanup steps at the start of your pipeline
- Review idempotency of your commands

## See Also

- [BUILD-FILE.md](BUILD-FILE.md) - Complete build file reference
- [examples/retry-example.yaml](../examples/retry-example.yaml) - Working examples
