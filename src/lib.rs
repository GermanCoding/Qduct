pub mod tunnel;

#[derive(clap::Args, Debug)]
pub struct CommonArgs {
    #[clap(long)]
    udp_server: bool,
}
