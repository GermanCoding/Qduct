pub mod tunnel;

#[derive(clap::Args, Debug)]
pub struct CommonArgs {
    /// If set, automatically trust the certificate of the peer. You still need to cross-check certificate words to detect active attacks.
    #[clap(long, short)]
    trust: bool,
}
