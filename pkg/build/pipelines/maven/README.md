<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [maven/configure-mirror](#mavenconfigure-mirror)
- [maven/pombump](#mavenpombump)

## maven/configure-mirror

Configure GCP Maven Central mirror for faster downloads

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |

## maven/pombump

Run pombump tool to update versions and properties in a Maven POM file

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| debug | false | Enable debug mode, which will print out the diffs of the pom.xml file after running pombump  | false |
| dependencies | false | Dependencies to be used for updating the POM file via command line flag  |  |
| patch-file | false | Patches file to use for updating the POM file  | ./pombump-deps.yaml |
| pom | false | Path to pom.xml  | pom.xml |
| properties | false | Properties to update / add the POM file via command line flag  |  |
| properties-file | false | Properties file to be used for updating the POM file  | ./pombump-properties.yaml |
| show-dependency-tree | false | Display a dependency tree for the existing pom.xml file | false |


<!-- end:pipeline-reference-gen -->