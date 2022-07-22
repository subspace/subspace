// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

//! Light client substrate primitives for Subspace.
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_arithmetic::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, CompatibleDigestItem, Error as DigestError,
    ErrorDigestType, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::traits::Header as HeaderT;
use sp_std::cmp::Ordering;
use subspace_core_primitives::{Randomness, RewardSignature, Salt};
use subspace_solving::{derive_global_challenge, derive_target, REWARD_SIGNING_CONTEXT};
use subspace_verification::{
    check_reward_signature, derive_next_solution_range, derive_randomness, verify_solution,
    VerifySolutionParams,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mock;

// TODO(ved): move them to consensus primitives and change usages across
/// Type of solution range
type SolutionRange = u64;

/// BlockWeight type for fork choice rules
type BlockWeight = u128;

/// Eon Index type
type EonIndex = u64;

/// HeaderExt describes an extended block chain header at a specific height along with some computed values.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct HeaderExt<Header> {
    /// Actual header of the subspace block chain at a specific height
    pub header: Header,
    /// Cumulative weight of chain until this header
    pub total_weight: BlockWeight,
    /// Current Eon index
    pub eon_index: EonIndex,

    #[cfg(test)]
    pub(crate) overrides: mock::TestOverrides,
}

impl<Header: HeaderT> HeaderExt<Header> {
    pub(crate) fn derive_digest_items<Store: Storage<Header>>(
        &self,
        store: &Store,
    ) -> Result<
        SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature>,
        ImportError<HashOf<Header>>,
    > {
        let constants = store.constants();
        let mut digest_items = extract_subspace_digest_items(&self.header)
            .map_err(ImportError::DigestExtractionError)?;

        // derive global randomness if interval is met
        digest_items.global_randomness = self.derive_global_randomness(
            constants.randomness_interval,
            &digest_items.pre_digest,
            digest_items.global_randomness,
        )?;

        // derive solution range if interval is met
        digest_items.solution_range = self.derive_solution_range(
            store,
            constants.era_duration,
            constants.slot_probability,
            digest_items.solution_range,
            digest_items.pre_digest.slot,
        )?;

        // derive salt if interval is met
        digest_items.salt = self.derive_salt(digest_items.salt);

        Ok(digest_items)
    }

    fn derive_global_randomness(
        &self,
        global_randomness_interval: NumberOf<Header>,
        pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
        current_randomness: Randomness,
    ) -> Result<Randomness, ImportError<HashOf<Header>>> {
        if *self.header.number() % global_randomness_interval == Zero::zero() {
            derive_randomness(
                &Into::<subspace_core_primitives::PublicKey>::into(&pre_digest.solution.public_key),
                pre_digest.solution.tag,
                &pre_digest.solution.tag_signature,
            )
            .map_err(|_err| ImportError::DigestDerivationError(ErrorDigestType::GlobalRandomness))
        } else {
            Ok(current_randomness)
        }
    }

    fn derive_solution_range<Store: Storage<Header>>(
        &self,
        store: &Store,
        era_duration: NumberOf<Header>,
        slot_probability: (u64, u64),
        current_solution_range: SolutionRange,
        current_slot: Slot,
    ) -> Result<SolutionRange, ImportError<HashOf<Header>>> {
        #[cfg(test)]
        if self.overrides.solution_range.is_some() {
            return Ok(self.overrides.solution_range.unwrap());
        }

        if *self.header.number() % era_duration == Zero::zero() {
            // Era start slot is slot at (current number - Era duration) block
            let mut ancestor_number = self
                .header
                .number()
                .checked_sub(&era_duration)
                .expect("should not under flow due to the check above");

            // if the ancestor we are looking for is Genesis block, we need to adjust that
            // since the Genesis block will not have any slot. So we fallback to Block #1
            if ancestor_number == Zero::zero() {
                ancestor_number = One::one();
            }

            // fetch the ancestor
            let ancestor = store
                .ancestor_of_header_at_depth(ancestor_number, self)
                .ok_or(ImportError::DigestDerivationError(
                    ErrorDigestType::SolutionRange,
                ))?;

            // extract ancestor's digests
            let ancestor_digests = extract_subspace_digest_items::<
                Header,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&ancestor.header)?;
            let era_start_slot = u64::from(ancestor_digests.pre_digest.slot);
            let current_slot = u64::from(current_slot);

            // derive solution range
            Ok(derive_next_solution_range(
                era_start_slot,
                current_slot,
                slot_probability,
                current_solution_range,
                era_duration
                    .try_into()
                    .unwrap_or_else(|_| panic!("Era duration is always within u64; qed")),
            ))
        } else {
            Ok(current_solution_range)
        }
    }

    fn derive_salt(&self, current_salt: Salt) -> Salt {
        current_salt
    }
}

type HashOf<T> = <T as HeaderT>::Hash;
type NumberOf<T> = <T as HeaderT>::Number;

/// Chain constants
#[derive(Debug, Clone)]
pub struct ChainConstants<Header: HeaderT> {
    /// Interval at which randomness is updated
    pub randomness_interval: NumberOf<Header>,
    /// Era duration
    pub era_duration: NumberOf<Header>,
    /// K Depth at which we finalize the heads
    pub k_depth: NumberOf<Header>,
    /// Slot probability of the chain
    pub slot_probability: (u64, u64),
    /// Eon duration
    pub eon_duration: u64,
}

/// Storage responsible for storing headers
pub trait Storage<Header: HeaderT> {
    /// Chain constants
    fn constants(&self) -> ChainConstants<Header>;

    /// Queries a header at a specific block number or block hash
    fn header(&self, hash: HashOf<Header>) -> Option<HeaderExt<Header>>;

    /// Stores the extended header.
    /// as_best_header signifies of the header we are importing is considered best
    fn store_header(&mut self, header_ext: HeaderExt<Header>, as_best_header: bool);

    /// Returns the best known tip of the canonical chain
    fn best_header(&self) -> HeaderExt<Header>;

    /// Finalizes the header, prunes and returns all the fork headers at that number
    fn finalize_header(&mut self, hash: HashOf<Header>) -> Vec<HeaderExt<Header>>;

    /// Finalized number and hash of the header
    /// Genesis head is always finalized since the beginning
    fn finalized_head(&self) -> (NumberOf<Header>, HashOf<Header>);

    /// Returns the total heads present at the number.
    fn heads_at_number(&self, number: NumberOf<Header>) -> Vec<HashOf<Header>>;

    /// Prunes the headers at number whose parent matches with provided parents
    fn prune_headers_with_parents_at_number(
        &mut self,
        number: NumberOf<Header>,
        parents: Vec<HashOf<Header>>,
    ) -> Vec<HeaderExt<Header>>;

    /// Returns the ancestor of the header at depth provided
    fn ancestor_of_header_at_depth(
        &self,
        depth: NumberOf<Header>,
        header: &HeaderExt<Header>,
    ) -> Option<HeaderExt<Header>> {
        if *header.header.number() < depth {
            return None;
        }

        // short circuit if the depth is at the same or lower number than finalized head
        let (finalized_number, _) = self.finalized_head();
        if depth.le(&finalized_number) {
            return self.header(self.heads_at_number(depth)[0]);
        }

        // start tree route till the ancestor
        let mut header = header.to_owned();
        while *header.header.number() > depth {
            header = self.header(*header.header.parent_hash())?;
        }

        Some(header)
    }

    /// Finalize the block at k-depth from the best block and prune remaining forks if any.
    /// Note: at the moment, it is assumed that light client must always begin with genesis
    /// But with some minor changes, we can introduce some trusted checkpoint so that light client
    /// is synced with the chain much faster.
    fn finalize_and_prune_forks(&mut self) -> Result<(), ImportError<HashOf<Header>>> {
        let k_depth = self.constants().k_depth;
        let best_header = self.best_header();
        let current_finalized_number = self.finalized_head().0;

        // ensure we have imported at least k-depth number of headers
        let number_to_finalize = match best_header.header.number().checked_sub(&k_depth) {
            // we have not progressed that far to finalize yet.
            None => {
                // explicitly set finalized head to genesis if it is not genesis.
                // this could happen when the re-org happens and a heavier smaller chain becomes canonical and
                // previous fork was long enough to have finalized some heads.
                if current_finalized_number > Zero::zero() {
                    self.finalize_header(self.heads_at_number(Zero::zero())[0]);
                }
                return Ok(());
            }
            Some(number) => number,
        };

        // we want to finalize the header from the current finalized header until the k-depth number of the best.
        // 1. An ideal scenario, the current finalized head is one number less than number to be finalized but
        // 2. if there was a re-org to longer chain when new header was imported, we do not want to miss
        //    pruning fork headers between current and to be finalized number. So we go number by number and prune fork headers.
        // 3. if there was a re-rg to a shorter chain when the new header was imported, then as per k-depth
        //    we would have finalized more headers and, unfortunately, would have pruned any valid forks
        //    There is not much we can do at this point then to just move the finalized head back and proceed.
        match number_to_finalize.cmp(&current_finalized_number) {
            // move the finalized head back to the expected head and return
            Ordering::Less => {
                let head_hash = self.heads_at_number(number_to_finalize)[0];
                self.finalize_header(head_hash);
            }
            // nothing to do as we finalized the header already.
            Ordering::Equal => (),
            // move step by step from current to expected and prune all fork headers
            Ordering::Greater => {
                let mut current_finalized_number = current_finalized_number;

                while current_finalized_number < number_to_finalize {
                    current_finalized_number = current_finalized_number
                        .checked_add(&One::one())
                        .expect("should not overflow");

                    // find the ancestor of the best header at k-depth
                    let ancestor_header = self
                        .ancestor_of_header_at_depth(current_finalized_number, &best_header)
                        .expect("ancestor must exist at this point in time");

                    // finalize the ancestor
                    let mut number = *ancestor_header.header.number();
                    let mut pruned_headers = self.finalize_header(ancestor_header.header.hash());

                    // start pruning descendants of the forks at the finalized number
                    while !pruned_headers.is_empty() {
                        number = number
                            .checked_add(&One::one())
                            .expect("should not overflow");
                        pruned_headers = self.prune_headers_with_parents_at_number(
                            number,
                            pruned_headers
                                .into_iter()
                                .map(|header| header.header.hash())
                                .collect(),
                        );
                    }
                }
            }
        };

        Ok(())
    }
}

/// Error during the header import.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError<Hash> {
    /// Header already imported.
    HeaderAlreadyImported,
    /// Header we are trying to import is not part of the canonical chain
    NonCanonicalHeader,
    /// Missing parent header
    MissingParent(Hash),
    /// Error while extracting digests from header
    DigestExtractionError(DigestError),
    /// Invalid digest in the header
    InvalidDigest(ErrorDigestType),
    /// Invalid slot when compared with parent header
    InvalidSlot,
    /// Block signature is invalid
    InvalidBlockSignature,
    /// Invalid solution
    InvalidSolution(subspace_verification::Error),
    /// Digest derivation error
    DigestDerivationError(ErrorDigestType),
}

impl<Hash> From<DigestError> for ImportError<Hash> {
    fn from(error: DigestError) -> Self {
        ImportError::DigestExtractionError(error)
    }
}

/// Verifies and import headers.
pub trait HeaderImporter<Header: HeaderT, Store: Storage<Header>> {
    /// Verifies header, computes consensus values for block progress and stores the HeaderExt.
    fn import_header(
        store: &mut Store,
        mut header: Header,
    ) -> Result<(), ImportError<HashOf<Header>>> {
        // check if the header is already imported
        match store.header(header.hash()) {
            Some(_) => Err(ImportError::HeaderAlreadyImported),
            None => Ok(()),
        }?;

        // only try and import headers above the finalized height
        if *header.number() <= store.finalized_head().0 {
            return Err(ImportError::NonCanonicalHeader);
        }

        // fetch parent header
        let parent_header = store
            .header(*header.parent_hash())
            .ok_or_else(|| ImportError::MissingParent(header.hash()))?;

        // TODO(ved): check for farmer equivocation

        // verify global randomness, solution range, and salt from the parent header
        let SubspaceDigestItems {
            pre_digest,
            signature: _,
            global_randomness,
            solution_range,
            salt,
        } = verify_header_digest_with_parent(store, &parent_header, &header)?;

        // slot must be strictly increasing from the parent header
        verify_slot(&parent_header.header, &pre_digest)?;

        // verify block signature
        verify_block_signature(&mut header, &pre_digest.solution.public_key)?;

        // verify solution
        verify_solution(
            &pre_digest.solution,
            pre_digest.slot.into(),
            VerifySolutionParams {
                global_randomness: &global_randomness,
                solution_range,
                salt,
                // TODO(ved): verify POAS once we have access to record root
                piece_check_params: None,
            },
        )
        .map_err(ImportError::InvalidSolution)?;

        let block_weight = calculate_block_weight(&global_randomness, &pre_digest);
        let total_weight = parent_header.total_weight + block_weight;

        // last best header should ideally be parent header. if not check for forks and pick the best chain
        let last_best_header = store.best_header();
        let is_best_header = if last_best_header.header.hash() == parent_header.header.hash() {
            // header is extending the current best header. consider this best header
            true
        } else {
            let last_best_weight = last_best_header.total_weight;
            match total_weight.cmp(&last_best_weight) {
                // current weight is greater than last best. pick this header as best
                Ordering::Greater => true,
                // if weights are equal, pick the longest chain
                Ordering::Equal => header.number() > last_best_header.header.number(),
                // we already are on the best chain
                Ordering::Less => false,
            }
        };

        // TODO(ved): extract record roots from the header
        // TODO(ved); extract an equivocations from the header

        // derive eon index
        let next_eon_index = if *header.number() == One::one() {
            // since this is the first block, just return the eon index of the parent which is always 0.
            parent_header.eon_index
        } else {
            // since genesis wont have a slot, we take the slot of the block #1
            let genesis = store
                .ancestor_of_header_at_depth(One::one(), &parent_header)
                .expect("ancestor must be present at this time");
            let genesis_digests = extract_subspace_digest_items::<
                Header,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&genesis.header)?;
            derive_next_eon_index(
                parent_header.eon_index,
                store.constants().eon_duration,
                genesis_digests.pre_digest.slot,
                pre_digest.slot,
            )
        };

        let header_ext = HeaderExt {
            header,
            total_weight,
            eon_index: next_eon_index,

            #[cfg(test)]
            overrides: Default::default(),
        };

        // store header
        store.store_header(header_ext, is_best_header);

        // finalize and prune forks if the chain has progressed
        if is_best_header {
            store.finalize_and_prune_forks()?;
        }

        Ok(())
    }
}

fn verify_header_digest_with_parent<Header: HeaderT, Store: Storage<Header>>(
    store: &Store,
    parent_header: &HeaderExt<Header>,
    header: &Header,
) -> Result<
    SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature>,
    ImportError<HashOf<Header>>,
> {
    let pre_digest_items = extract_subspace_digest_items(header)?;
    let parent_digest_items = parent_header.derive_digest_items(store)?;
    if pre_digest_items.global_randomness != parent_digest_items.global_randomness {
        return Err(ImportError::InvalidDigest(
            ErrorDigestType::GlobalRandomness,
        ));
    }

    if pre_digest_items.solution_range != parent_digest_items.solution_range {
        return Err(ImportError::InvalidDigest(ErrorDigestType::SolutionRange));
    }

    if pre_digest_items.salt != parent_digest_items.salt {
        return Err(ImportError::InvalidDigest(ErrorDigestType::Salt));
    }

    Ok(pre_digest_items)
}

fn verify_slot<Header: HeaderT>(
    parent_header: &Header,
    pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
) -> Result<(), ImportError<HashOf<Header>>> {
    let parent_pre_digest = extract_pre_digest(parent_header)?;

    if pre_digest.slot <= parent_pre_digest.slot {
        return Err(ImportError::InvalidSlot);
    }

    Ok(())
}

// verifies the block signature present as part of the last digest log
fn verify_block_signature<Header: HeaderT>(
    header: &mut Header,
    public_key: &FarmerPublicKey,
) -> Result<(), ImportError<HashOf<Header>>> {
    let seal = header
        .digest_mut()
        .pop()
        .ok_or(ImportError::DigestExtractionError(DigestError::Missing(
            ErrorDigestType::Seal,
        )))?;

    let signature = seal
        .as_subspace_seal()
        .ok_or(ImportError::InvalidDigest(ErrorDigestType::Seal))?;

    // The pre-hash of the header doesn't include the seal and that's what we sign
    let pre_hash = header.hash();

    // Verify that block is signed properly
    check_reward_signature(
        pre_hash.as_ref(),
        &Into::<RewardSignature>::into(&signature),
        &Into::<subspace_core_primitives::PublicKey>::into(public_key),
        &schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
    )
    .map_err(|_| ImportError::InvalidBlockSignature)?;

    // push the seal back into the header
    header.digest_mut().push(seal);
    Ok(())
}

fn calculate_block_weight(
    global_randomness: &Randomness,
    pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
) -> BlockWeight {
    let global_challenge = derive_global_challenge(global_randomness, pre_digest.slot.into());

    let target = u64::from_be_bytes(
        derive_target(
            &schnorrkel::PublicKey::from_bytes(pre_digest.solution.public_key.as_ref())
                .expect("Always correct length; qed"),
            global_challenge,
            &pre_digest.solution.local_challenge,
        )
        .expect("Verification of the local challenge was done before this; qed"),
    );
    let tag = u64::from_be_bytes(pre_digest.solution.tag);
    u128::from(u64::MAX - subspace_core_primitives::bidirectional_distance(&target, &tag))
}

fn derive_next_eon_index(
    parent_eon_index: u64,
    eon_duration: u64,
    genesis_slot: Slot,
    current_slot: Slot,
) -> EonIndex {
    // calculate current eon start slot from (eon_index * eon_duration) + genesis_slot
    let current_eon_start_slot = parent_eon_index
        .checked_mul(eon_duration)
        .and_then(|res| res.checked_add(u64::from(genesis_slot)))
        .expect("eon start slot should fit into u64");

    let should_eon_change = current_slot.saturating_sub(current_eon_start_slot) >= eon_duration;
    if should_eon_change {
        current_slot
            .checked_sub(u64::from(genesis_slot))
            .expect("Current slot is never lower than genesis slot; qed")
            .checked_div(eon_duration)
            .expect("Eon duration is never zero; qed")
    } else {
        parent_eon_index
    }
}
