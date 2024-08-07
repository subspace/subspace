// Copyright (C) 2024 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pallet object mapping, used to map blocks and transactions to their DSN storage.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

// TODO: mock and tests

pub use pallet::*;
use subspace_core_primitives::{Blake3Hash, PieceIndex};

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use log::debug;
    use subspace_core_primitives::{Blake3Hash, PieceIndex};

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    /// Pallet object-mapping, used used to map blocks and transactions to their DSN storage.
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// TODO: are there named type wrappers for piece offset and object size?
    #[pallet::storage]
    pub(super) type ObjectMappingStorage<T: Config> =
        StorageMap<_, Blake2_128Concat, Blake3Hash, (PieceIndex, u32, u32)>;

    #[pallet::error]
    pub enum Error<T> {
        /// There is no mapping for the requested object
        NoSuchObjectMapping,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Add a new object mapping to the runtime mappings.
        /// Objects are keyed by their IDs, and retrieved using the first piece location and size.
        ///
        /// TODO:
        /// - make the domain(?) call this from system.remark(?) as mappings are discovered/added
        /// - should this be feeless? what is the weight?
        #[pallet::call_index(0)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn add_mapping(
            origin: OriginFor<T>,
            object_id: Blake3Hash,
            first_piece_index: PieceIndex,
            first_piece_offset: u32,
            object_size: u32,
        ) -> DispatchResult {
            // TODO: do we need to check for a specific sender?
            let _sender = ensure_signed(origin)?;

            debug!(
                target: "runtime:object-mapping",
                "Adding object mapping {}, piece index {}, piece offset {}, size {} bytes",
                hex::encode(object_id),
                first_piece_index,
                first_piece_offset,
                object_size
            );

            // TODO: do we error or replace if the object_id already exists?
            ObjectMappingStorage::<T>::insert(
                object_id,
                (first_piece_index, first_piece_offset, object_size),
            );

            Ok(())
        }

        /// Get an object mapping from the stored runtime mappings.
        /// Objects are keyed by their IDs, and retrieved using the first piece location and size.
        ///
        /// TODO: should this be feeless? what is the weight?
        #[pallet::call_index(1)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn get_mapping(origin: OriginFor<T>, object_id: Blake3Hash) -> DispatchResult {
            // TODO: do we need to check for a specific sender?
            let _sender = ensure_signed(origin)?;

            debug!(
                target: "runtime:object-mapping",
                "Looking up object mapping {}",
                hex::encode(object_id),
            );

            let (first_piece_index, first_piece_offset, object_size) =
                ObjectMappingStorage::<T>::get(object_id).ok_or(Error::<T>::NoSuchObjectMapping)?;

            debug!(
                target: "runtime:object-mapping",
                "Found object mapping {}, piece index {}, piece offset {}, size {} bytes",
                hex::encode(object_id),
                first_piece_index,
                first_piece_offset,
                object_size
            );

            // TODO:
            // - this mapping needs to be used to fetch the data, then the data needs to go to the caller
            // - write an RPC(?) that fetches this mapping, then uses the mapping to fetch the object
            let _returned_mapping = (
                object_id,
                first_piece_index,
                first_piece_offset,
                object_size,
            );

            Ok(())
        }
    }
}

/// Mapping from the object hash to its piece, offset, and size
#[derive(Debug)]
pub struct ObjectMapping {
    /// Object hash
    pub object_id: Blake3Hash,
    // Index of the first piece containing the start of the object
    pub first_piece_index: PieceIndex,
    /// Offset of object in the first piece
    pub first_piece_offset: u32,
    /// Object size
    pub object_size: u32,
}

impl<T: Config> Call<T> {
    /// Extract object location if an extrinsic corresponds to `add_mapping` call
    pub fn extract_add_mapping(&self) -> Option<ObjectMapping> {
        match self {
            Self::add_mapping {
                object_id,
                first_piece_index,
                first_piece_offset,
                object_size,
            } => {
                // `0` corresponds to `Call::add_mapping {}` enum variant encoding.
                Some(ObjectMapping {
                    object_id: *object_id,
                    first_piece_index: *first_piece_index,
                    first_piece_offset: *first_piece_offset,
                    object_size: *object_size,
                })
            }
            _ => None,
        }
    }

    /// Extract object hash if an extrinsic corresponds to `get_mapping` call
    pub fn extract_get_mapping(&self) -> Option<Blake3Hash> {
        match self {
            Self::get_mapping { object_id } => {
                // `1` corresponds to `Call::get_mapping {}` enum variant encoding.
                Some(*object_id)
            }
            _ => None,
        }
    }
}
