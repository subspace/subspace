// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::domain::evm_chain_spec::{self, SpecId};
use clap::Parser;
use domain_runtime_primitives::opaque::{Block as DomainBlock, Header as DomainHeader};
use domain_runtime_primitives::DomainCoreApi;
use parity_scale_codec::{Decode, Encode};
use sc_cli::{
    BlockNumberOrHash, ChainSpec, CliConfiguration, DefaultConfigurationValues, ImportParams,
    KeystoreParams, NetworkParams, Result, Role, RunCmd as SubstrateRunCmd, SharedParams,
    SubstrateCli,
};
use sc_client_api::backend::AuxStore;
use sc_client_api::BlockBackend;
use sc_service::config::PrometheusConfig;
use sc_service::{BasePath, Configuration};
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domain_digests::AsPredigest;
use sp_domains::storage::RawGenesis;
use sp_domains::{DomainId, DomainsApi, OperatorId};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header};
use sp_runtime::{BuildStorage, DigestItem};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::io::Write;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::path::PathBuf;
use subspace_core_primitives::U256;
use subspace_runtime_primitives::opaque::Block as CBlock;

/// Sub-commands supported by the executor.
#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Subcommand {
    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// Build the genesis storage of the evm domain chain in json format
    BuildGenesisStorage(BuildGenesisStorageCmd),

    /// The `export-execution-receipt` command used to get the ER from the auxiliary storage of the operator client
    ExportExecutionReceipt(ExportExecutionReceiptCmd),

    /// The `re-validate-bundle` command used to re-validate bundle at the given
    /// consensus block against the domain chain state at a given domain block
    ReValidateBundle(ReValidateBundleCmd),
}

fn parse_domain_id(s: &str) -> std::result::Result<DomainId, ParseIntError> {
    s.parse::<u32>().map(Into::into)
}

fn parse_operator_id(s: &str) -> std::result::Result<OperatorId, ParseIntError> {
    s.parse::<u64>().map(OperatorId::from)
}

#[derive(Debug, Parser)]
pub struct DomainCli {
    /// Run a domain node.
    #[clap(flatten)]
    pub run: SubstrateRunCmd,

    #[clap(long, value_parser = parse_domain_id)]
    pub domain_id: DomainId,

    /// Use provider operator id to submit bundles.
    #[arg(long, value_parser = parse_operator_id)]
    pub operator_id: Option<OperatorId>,

    /// Additional args for domain.
    #[clap(raw = true)]
    additional_args: Vec<String>,
}

impl DomainCli {
    /// Constructs a new instance of [`DomainCli`].
    pub fn new(
        consensus_base_path: Option<PathBuf>,
        domain_args: impl Iterator<Item = String>,
    ) -> Self {
        let mut cli =
            DomainCli::parse_from([Self::executable_name()].into_iter().chain(domain_args));

        // Use `consensus_base_path/domain-{domain_id}` as the domain base path if it's not
        // specified explicitly but there is an explicit consensus base path.
        match consensus_base_path {
            Some(c_path) if cli.run.shared_params.base_path.is_none() => {
                cli.run
                    .shared_params
                    .base_path
                    .replace(c_path.join(format!("domain-{}", u32::from(cli.domain_id))));
            }
            _ => {}
        }

        cli
    }

    pub fn additional_args(&self) -> impl Iterator<Item = String> {
        [Self::executable_name()]
            .into_iter()
            .chain(self.additional_args.clone())
    }

    /// Creates domain configuration from domain cli.
    pub fn create_domain_configuration(
        &self,
        tokio_handle: tokio::runtime::Handle,
    ) -> sc_cli::Result<Configuration> {
        let service_config = SubstrateCli::create_configuration(self, self, tokio_handle)?;
        Ok(service_config)
    }
}

impl SubstrateCli for DomainCli {
    fn impl_name() -> String {
        "Subspace Domain".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn executable_name() -> String {
        // Customize to make sure directory used for data by default is the same regardless of the
        // name of the executable file.
        "subspace-node".to_string()
    }

    fn description() -> String {
        "Subspace Domain".into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/subspace/subspace/issues/new".into()
    }

    fn copyright_start_year() -> i32 {
        2022
    }

    fn load_spec(&self, id: &str) -> std::result::Result<Box<dyn ChainSpec>, String> {
        // TODO: Fetch the runtime name of `self.domain_id` properly.
        let runtime_name = "evm";
        match runtime_name {
            "evm" => evm_chain_spec::load_chain_spec(id),
            unknown_name => Err(format!("Unknown runtime: {unknown_name}")),
        }
    }
}

impl DefaultConfigurationValues for DomainCli {
    fn p2p_listen_port() -> u16 {
        30334
    }

    fn rpc_listen_port() -> u16 {
        9945
    }

    fn prometheus_listen_port() -> u16 {
        9616
    }
}

impl CliConfiguration<Self> for DomainCli {
    fn shared_params(&self) -> &SharedParams {
        self.run.shared_params()
    }

    fn import_params(&self) -> Option<&ImportParams> {
        self.run.import_params()
    }

    fn network_params(&self) -> Option<&NetworkParams> {
        self.run.network_params()
    }

    fn keystore_params(&self) -> Option<&KeystoreParams> {
        self.run.keystore_params()
    }

    fn base_path(&self) -> Result<Option<BasePath>> {
        self.shared_params().base_path()
    }

    fn rpc_addr(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.rpc_addr(default_listen_port)
    }

    fn prometheus_config(
        &self,
        default_listen_port: u16,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<PrometheusConfig>> {
        self.run.prometheus_config(default_listen_port, chain_spec)
    }

    fn chain_id(&self, is_dev: bool) -> Result<String> {
        self.run.chain_id(is_dev)
    }

    fn role(&self, _is_dev: bool) -> Result<sc_service::Role> {
        if self.run.validator {
            return Err(sc_cli::Error::Input(
                "use `--operator-id` argument to run as operator".to_string(),
            ));
        }

        // is authority when operator_id is passed.
        let is_authority = self.operator_id.is_some();

        Ok(if is_authority {
            Role::Authority
        } else {
            Role::Full
        })
    }

    fn transaction_pool(&self, is_dev: bool) -> Result<sc_service::config::TransactionPoolOptions> {
        self.run.transaction_pool(is_dev)
    }

    fn trie_cache_maximum_size(&self) -> Result<Option<usize>> {
        self.run.trie_cache_maximum_size()
    }

    fn rpc_methods(&self) -> Result<sc_service::config::RpcMethods> {
        self.run.rpc_methods()
    }

    fn rpc_max_connections(&self) -> Result<u32> {
        self.run.rpc_max_connections()
    }

    fn rpc_cors(&self, is_dev: bool) -> Result<Option<Vec<String>>> {
        self.run.rpc_cors(is_dev)
    }

    fn default_heap_pages(&self) -> Result<Option<u64>> {
        self.run.default_heap_pages()
    }

    fn force_authoring(&self) -> Result<bool> {
        self.run.force_authoring()
    }

    fn disable_grandpa(&self) -> Result<bool> {
        self.run.disable_grandpa()
    }

    fn max_runtime_instances(&self) -> Result<Option<usize>> {
        self.run.max_runtime_instances()
    }

    fn announce_block(&self) -> Result<bool> {
        self.run.announce_block()
    }

    fn dev_key_seed(&self, is_dev: bool) -> Result<Option<String>> {
        self.run.dev_key_seed(is_dev)
    }

    fn telemetry_endpoints(
        &self,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<sc_telemetry::TelemetryEndpoints>> {
        self.run.telemetry_endpoints(chain_spec)
    }
}

// TODO: make the command generic over different runtime type instead of just the evm domain runtime
/// The `build-genesis-storage` command used to build the genesis storage of the evm domain chain.
#[derive(Debug, Clone, Parser)]
pub struct BuildGenesisStorageCmd {
    /// The base struct of the build-genesis-storage command.
    #[clap(flatten)]
    pub shared_params: SharedParams,
}

impl BuildGenesisStorageCmd {
    /// Run the build-genesis-storage command
    pub fn run(&self) -> sc_cli::Result<()> {
        let is_dev = self.shared_params.is_dev();
        let chain_id = self.shared_params.chain_id(is_dev);
        let domain_genesis_config = match chain_id.as_str() {
            "gemini-3g" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::Gemini),
            "devnet" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::DevNet),
            "dev" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::Dev),
            "" | "local" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::Local),
            unknown_id => {
                eprintln!(
                    "unknown chain {unknown_id:?}, expected gemini-3g, devnet, dev, or local",
                );
                return Ok(());
            }
        };

        let raw_genesis_storage = {
            let storage = domain_genesis_config
                .build_storage()
                .expect("Failed to build genesis storage from genesis runtime config");
            let raw_genesis = RawGenesis::from_storage(storage);
            raw_genesis.encode()
        };

        if std::io::stdout()
            .write_all(raw_genesis_storage.as_ref())
            .is_err()
        {
            let _ = std::io::stderr().write_all(b"Error writing to stdout\n");
        }
        Ok(())
    }
}

/// The `export-execution-receipt` command used to get the ER from the auxiliary storage of the operator client
#[derive(Debug, Clone, Parser)]
pub struct ExportExecutionReceiptCmd {
    /// Get the `ExecutionReceipt` by domain block number or hash
    #[arg(long, conflicts_with_all = &["consensus_block_hash"])]
    pub domain_block: Option<BlockNumberOrHash>,

    /// Get the `ExecutionReceipt` by consensus block hash
    #[arg(long, conflicts_with_all = &["domain_block"])]
    pub consensus_block_hash: Option<BlockNumberOrHash>,

    /// The base struct of the export-execution-receipt command.
    #[clap(flatten)]
    pub shared_params: SharedParams,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node export-execution-receipt [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    pub domain_args: Vec<String>,
}

impl CliConfiguration for ExportExecutionReceiptCmd {
    fn shared_params(&self) -> &SharedParams {
        &self.shared_params
    }
}

impl ExportExecutionReceiptCmd {
    /// Run the export-execution-receipt command
    pub fn run<Backend, Client>(
        &self,
        domain_client: &Client,
        domain_backend: &Backend,
    ) -> sc_cli::Result<()>
    where
        Backend: AuxStore,
        Client: HeaderBackend<DomainBlock>,
    {
        let consensus_block_hash = match (&self.consensus_block_hash, &self.domain_block) {
            // Get ER by consensus block hash
            (Some(raw_consensus_block_hash), None) => {
                match raw_consensus_block_hash.parse::<CBlock>()? {
                    BlockId::Hash(h) => h,
                    BlockId::Number(_) => {
                        eprintln!(
                            "unexpected input {raw_consensus_block_hash:?}, expected consensus block hash",
                        );
                        return Ok(());
                    }
                }
            }
            // Get ER by domain block hash or number
            (None, Some(raw_domain_block)) => {
                let domain_block_hash = match raw_domain_block.parse::<DomainBlock>()? {
                    BlockId::Hash(h) => h,
                    BlockId::Number(number) => domain_client.hash(number)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Domain block hash for #{number:?} not found",
                        ))
                    })?,
                };
                let domain_header = domain_client.header(domain_block_hash)?.ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!(
                        "Header for domain block {domain_block_hash:?} not found"
                    ))
                })?;

                domain_header
                    .digest()
                    .convert_first(DigestItem::as_consensus_block_info)
                    .ok_or_else(|| {
                        sp_blockchain::Error::Application(Box::from(
                            "Domain block header for {domain_hash:?} must have consensus block info predigest"
                        ))
                    })?
            }
            _ => {
                eprintln!("Expect the domain-block or consensus-block-hash argument",);
                return Ok(());
            }
        };

        match domain_client_operator::load_execution_receipt::<Backend, DomainBlock, CBlock>(
            domain_backend,
            consensus_block_hash,
        )? {
            Some(er) => {
                println!("ExecutionReceipt of consensus block {consensus_block_hash:?}:\n{er:?}",);
            }
            None => {
                println!("ExecutionReceipt of consensus block {consensus_block_hash:?} not found",);
            }
        }
        Ok(())
    }
}

/// This `re-validate-bundle` command used to re-validate bundle at the given consensus block
/// against the domain chain state at a given domain block
#[derive(Debug, Clone, Parser)]
#[group(skip)]
pub struct ReValidateBundleCmd {
    /// Get the domain block by block number or hash
    #[arg(long)]
    pub domain_block: Option<BlockNumberOrHash>,

    /// Get the consensus block by block number or hash
    #[arg(long)]
    pub consensus_block: Option<BlockNumberOrHash>,

    /// The base struct of the re-validate-bundle command.
    #[clap(flatten)]
    pub shared_params: SharedParams,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node purge-chain [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    pub domain_args: Vec<String>,
}

impl CliConfiguration for ReValidateBundleCmd {
    fn shared_params(&self) -> &SharedParams {
        &self.shared_params
    }
}

impl ReValidateBundleCmd {
    /// Run the `re-validate-bundle` command
    pub fn run<Client, CClient>(
        &self,
        domain_id: DomainId,
        domain_client: &Client,
        consensus_client: &CClient,
    ) -> sp_blockchain::Result<()>
    where
        Client:
            HeaderBackend<DomainBlock> + BlockBackend<DomainBlock> + ProvideRuntimeApi<DomainBlock>,
        Client::Api: DomainCoreApi<DomainBlock> + TaggedTransactionQueue<DomainBlock>,
        CClient: HeaderBackend<CBlock> + BlockBackend<CBlock> + ProvideRuntimeApi<CBlock>,
        CClient::Api: DomainsApi<CBlock, DomainHeader>,
    {
        let (consensus_block_number, consensus_block_hash) = match &self.consensus_block {
            None => (
                consensus_client.info().best_number,
                consensus_client.info().best_hash,
            ),
            Some(raw_consensus_block) => match raw_consensus_block.parse::<CBlock>() {
                Ok(BlockId::Hash(h)) => {
                    let number = consensus_client.number(h)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Consensus block number for #{h:?} not found",
                        ))
                    })?;
                    (number, h)
                }
                Ok(BlockId::Number(number)) => {
                    let hash = consensus_client.hash(number)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Consensus block hash for #{number:?} not found",
                        ))
                    })?;
                    (number, hash)
                }
                Err(e) => {
                    return Err(sp_blockchain::Error::Application(
                        format!("Failed to parse consensus block, err {e:?}",).into(),
                    ))
                }
            },
        };
        let (domain_block_number, domain_block_hash) = match &self.domain_block {
            None => (
                domain_client.info().best_number,
                domain_client.info().best_hash,
            ),
            Some(raw_domain_block) => match raw_domain_block.parse::<DomainBlock>() {
                Ok(BlockId::Hash(h)) => {
                    let number = domain_client.number(h)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Domain block number for #{h:?} not found",
                        ))
                    })?;
                    (number, h)
                }
                Ok(BlockId::Number(number)) => {
                    let hash = domain_client.hash(number)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Domain block hash for #{number:?} not found",
                        ))
                    })?;
                    (number, hash)
                }
                Err(e) => {
                    return Err(sp_blockchain::Error::Application(
                        format!("Failed to parse domain block, err {e:?}",).into(),
                    ))
                }
            },
        };

        // get bundle from consensus block
        let extrinsics = consensus_client
            .block_body(consensus_block_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Consensus block body of {consensus_block_hash:?} unavailable"
                ))
            })?;

        let bundles = consensus_client.runtime_api().extract_successful_bundles(
            consensus_block_hash,
            domain_id,
            extrinsics,
        )?;

        let tx_range = consensus_client
            .runtime_api()
            .domain_tx_range(consensus_block_hash, domain_id)?;

        println!(
            "Start re-validate {} bundles, consensus block {consensus_block_hash}#{consensus_block_number}, \
             domain block {domain_block_hash}#{domain_block_number}",
             bundles.len()
        );

        // Check validity of bundle
        let runtime_api = domain_client.runtime_api();
        let at = domain_block_hash;
        for (bundle_index, bundle) in bundles.into_iter().enumerate() {
            let bundle_vrf_hash =
                U256::from_be_bytes(bundle.sealed_header.header.proof_of_election.vrf_hash());
            let extrinsic_count = bundle.extrinsics.len();

            if extrinsic_count == 0 {
                println!("Empty bundle index {bundle_index}");
                continue;
            }

            for (ext_index, opaque_extrinsic) in bundle.extrinsics.iter().enumerate() {
                let Ok(extrinsic) = <<DomainBlock as BlockT>::Extrinsic>::decode(
                    &mut opaque_extrinsic.encode().as_slice(),
                ) else {
                    eprintln!(
                        "Invalid bundle index {bundle_index}, UndecodableTx index {ext_index}"
                    );
                    break;
                };

                let is_within_tx_range =
                    runtime_api.is_within_tx_range(at, &extrinsic, &bundle_vrf_hash, &tx_range)?;
                if !is_within_tx_range {
                    eprintln!(
                        "Invalid bundle index {bundle_index}, OutOfRangeTx index {ext_index}"
                    );
                    break;
                }

                let tx_validity = runtime_api.check_transaction_validity(
                    at,
                    &extrinsic,
                    domain_block_number,
                    at,
                )?;
                if let Err(validate_err) = tx_validity {
                    let validate_res = runtime_api.validate_transaction(
                        at,
                        TransactionSource::External,
                        extrinsic,
                        at,
                    )?;
                    let extrinsic_root = bundle.extrinsics_root();
                    eprintln!(
                        "Invalid bundle index {bundle_index}, IllegalTx index {ext_index}, extrinsic_root {extrinsic_root}, \
                         check tx validity error {:?}, bundle proposer validate result {validate_res:?}",
                         validate_err
                    );
                    break;
                }

                // Check if this extrinsic is an inherent extrinsic.
                if runtime_api.is_inherent_extrinsic(at, &extrinsic)? {
                    eprintln!(
                        "Invalid bundle index {bundle_index}, InherentExtrinsic index {ext_index}"
                    );
                    break;
                }

                if ext_index == extrinsic_count - 1 {
                    println!("Valid bundle index {bundle_index}");
                }
            }
        }

        Ok(())
    }
}
