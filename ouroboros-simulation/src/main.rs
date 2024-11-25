use ouroboros_simulation::network::*;
use clap::{Parser, Subcommand};
use ouroboros_simulation::parameters::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::fs::File;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Command {
    #[command(subcommand)]
    command: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    #[command(about = "Generate a random topology.")]
    Topology {
        #[arg(
            short = 'p',
            long = "parameter-file",
            value_name = "FILE",
            help = "Path to YAML-formatted parameters input file."
        )]
        parameter_filename: String,
        #[arg(
            short = 't',
            long = "topology-file",
            value_name = "FILE",
            help = "Path to JSON-formatted topology output file."
        )]
        topology_filename: String,
    },
}

fn main() {
    let args = Command::parse();
    match args.command {
        Action::Topology {
            parameter_filename,
            topology_filename,
        } => generate_topology(&parameter_filename, &topology_filename),
    }
}

fn generate_topology(parameter_filename: &String, topology_filename: &String) {
    let parameter_file = File::open(parameter_filename).expect("Failed opening parameters file.");
    let parameter_reader = std::io::BufReader::new(parameter_file);
    let parameters: Parameters =
        serde_yaml::from_reader(parameter_reader).expect("Failed reading parameters file.");
    let rng = &mut ChaCha8Rng::seed_from_u64(parameters.randomSeed);
    let topology = random_topology(rng, &parameters);
    let topology_file = File::create(topology_filename).expect("Failed creating topology file.");
    serde_json::to_writer(&topology_file, &topology).expect("Failed writing topology file.")
}
