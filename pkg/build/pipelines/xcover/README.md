<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [xcover/ensure](#xcoverensure)
- [xcover/profile](#xcoverprofile)
- [xcover/status](#xcoverstatus)
- [xcover/stop](#xcoverstop)
- [xcover/wait](#xcoverwait)

## xcover/ensure

Ensure a minimum coverage reported by xcover

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| min-coverage | false | The minimum coverage to accept as percentage. |  |
| package | false | The xcover package | xcover |

## xcover/profile

Start the coverage profile with the xcover tool

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| exclude-functions | false | The function symbols to exclude from profiling as a regular expression. |  |
| executable-path | true | The path to the executable of the application to test. |  |
| log-level | false | The log level of the xcover profile command. | info |
| package | false | The xcover package | xcover |
| verbose | false | Enable verbosity of the xcover profile command. It prints out all the functions being traced real-time. | false |
| wait-timeout | false | The maximum amount of time to wait for the xcover profiler to be ready for profiling, in seconds. | 60 |

## xcover/status

Check the status of xcover

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The xcover package | xcover |

## xcover/stop

Stop the xcover profiler tool

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The xcover package | xcover |

## xcover/wait

Wait for the xcover profiler to be ready

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The xcover package | xcover |
| wait-timeout | false | The maximum amount of time to wait for the xcover profiler to be ready for profiling, in seconds. | 60 |


<!-- end:pipeline-reference-gen -->