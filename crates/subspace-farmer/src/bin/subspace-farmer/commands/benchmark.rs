use crate::PosTable;
use anyhow::anyhow;
use clap::Subcommand;
use criterion::{black_box, BatchSize, Criterion, Throughput};
use parking_lot::Mutex;
use std::fs::OpenOptions;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Record, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_farm::farming::rayon_files::RayonFiles;
use subspace_farmer::single_disk_farm::farming::sync_fallback::SyncPlotAudit;
use subspace_farmer::single_disk_farm::farming::{PlotAudit, PlotAuditOptions};
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};
use subspace_farmer_components::sector::sector_size;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::SlotInfo;

/// Arguments for benchmark
#[derive(Debug, Subcommand)]
pub(crate) enum BenchmarkArgs {
    /// Audit benchmark
    Audit {
        /// Disk farm to audit
        ///
        /// Example:
        ///   /path/to/directory
        disk_farm: PathBuf,
        #[arg(long, default_value_t = 10)]
        sample_size: usize,
    },
}

pub(crate) fn benchmark(benchmark_args: BenchmarkArgs) -> anyhow::Result<()> {
    match benchmark_args {
        BenchmarkArgs::Audit {
            disk_farm,
            sample_size,
        } => audit(disk_farm, sample_size),
    }
}

fn audit(disk_farm: PathBuf, sample_size: usize) -> anyhow::Result<()> {
    let (single_disk_farm_info, disk_farm) = match SingleDiskFarm::collect_summary(disk_farm) {
        SingleDiskFarmSummary::Found { info, directory } => (info, directory),
        SingleDiskFarmSummary::NotFound { directory } => {
            return Err(anyhow!(
                "No single disk farm info found, make sure {} is a valid path to the farm and \
                process have permissions to access it",
                directory.display()
            ));
        }
        SingleDiskFarmSummary::Error { directory, error } => {
            return Err(anyhow!(
                "Failed to open single disk farm info, make sure {} is a valid path to the farm \
                and process have permissions to access it: {error}",
                directory.display()
            ));
        }
    };

    let sector_size = sector_size(single_disk_farm_info.pieces_in_sector());
    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let table_generator = Mutex::new(PosTable::generator());

    let sectors_metadata = SingleDiskFarm::read_all_sectors_metadata(&disk_farm)
        .map_err(|error| anyhow::anyhow!("Failed to read sectors metadata: {error}"))?;

    let mut criterion = Criterion::default().sample_size(sample_size);
    {
        let mut group = criterion.benchmark_group("audit");
        group.throughput(Throughput::Bytes(
            sector_size as u64 * sectors_metadata.len() as u64,
        ));
        {
            let plot = OpenOptions::new()
                .read(true)
                .open(disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;

            group.bench_function("plot/sync/single", |b| {
                let sync_plot_audit = SyncPlotAudit::new(&plot);

                b.iter_batched(
                    rand::random,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge,
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            maybe_sector_being_modified: None,
                            table_generator: &table_generator,
                        };

                        black_box(sync_plot_audit.audit(black_box(options)))
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        {
            let plot = RayonFiles::open(&disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;

            group.bench_function("plot/sync/rayon", |b| {
                let sync_plot_audit = SyncPlotAudit::new(&plot);

                b.iter_batched(
                    rand::random,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge,
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            maybe_sector_being_modified: None,
                            table_generator: &table_generator,
                        };

                        black_box(sync_plot_audit.audit(black_box(options)))
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }

    criterion.final_summary();

    Ok(())
}