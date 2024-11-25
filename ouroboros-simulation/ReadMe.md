# Network topology generator

A Rust program that reads a YAML-formatted set of network parameters and outputs a JSON topology for a randomly-generated network.


## Help

```console
$ cargo run
Usage: peras-topology <COMMAND>

Commands:
  topology  Generate a random topology.
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```console
$ cargo run -- topology --help

Generate a random topology.

Usage: peras-topology topology --parameter-file <FILE> --topology-file <FILE>

Options:
  -p, --parameter-file <FILE>  Path to YAML-formatted parameters input file.
  -t, --topology-file <FILE>   Path to JSON-formatted topology output file.
  -h, --help                   Print help
```


## Example

```console
$ cargo run -- topology --parameter-file example-parameters.yaml --topology-file example-topology.json

$ cat example-parameters.yaml 

randomSeed: 12345
endSlot: 100
peerCount: 10
downstreamCount: 3
totalStake: null
maximumStake: 1000
messageDelay: 0.35

$ cat example-topology.json 

{"connections":{"N1":["N9","N6","N2"],"N3":["N5","N6","N1"],"N9":["N10","N2","N8"],"N5":["N9","N1","N3"],"N2":["N8","N3","N5"],"N7":["N9","N8","N2"],"N8":["N6","N4","N5"],"N4":["N10","N3","N9"],"N6":["N7","N9","N3"],"N10":["N5","N8","N2"]}}
```
