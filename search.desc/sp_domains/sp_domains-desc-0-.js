searchState.loadedDescShard("sp_domains", 0, "Primitives for domains pallet.\nAnyone can operate for this domain.\nDomain bundle.\nA digest of the bundle\nIdentifier of a chain.\nHolds the current reserved balance for channel opening\nChannel identity.\nType holding the block details of confirmed domain block.\nExtrinsics shuffling seed\nActual extrinsic data that is inlined since it is less …\nDomain chains allowlist updates.\nPost hook to know if the domain had bundle submitted in …\nDomains specific digest item.\nUnique identifier of a domain.\n<code>DomainInstanceData</code> is used to construct the genesis …\nTrait to check domain owner.\nDomain Sudo runtime call. This structure exists because we …\nAPI necessary for domains pallet.\nDomains specific digest items.\nDomains specific Identifier for Balances holds.\nTrait that tracks the balances on Domains.\nEmpty extrinsics root.\nType representing domain epoch.\nReceipt of a domain block execution.\nRepresents the extrinsic either as full data or hash of …\nThe Trie root of all extrinsics included in a bundle.\nExtrinsic Hash.\nType alias for Header hash.\nType alias for Header Hashing.\nType alias for Header number.\nInitial tx range = U256::MAX / INITIAL_DOMAIN_TX_RANGE.\nTransaction is illegal (unable to pay the fee, etc).\n<code>InboxedBundle</code> represents a bundle that was successfully …\nTransaction is an inherent extrinsic.\nBundle invalidity type\nThe <code>estimated_bundle_weight</code> in the bundle header is invalid\nThe field <code>invalid_bundles</code> in <code>ExecutionReceipt</code> is invalid.\nReceipt invalidity type.\nTransaction is an invalid XDM.\nKey type for Operator.\nMessenger specific hold identifier\nHook to handle chain rewards.\nA hook to call after a domain is instantiated\nBundle with opaque extrinsics.\nList of <code>OpaqueBundle</code>.\nType that represents an operator allow list for Domains.\nType representing operator ID\nA type that implements <code>BoundToRuntimeAppPublic</code>, used for …\nAn operator authority keypair. Necessarily equivalent to …\nAn operator authority identifier.\nAn operator authority signature.\nPreimage to verify the proof of ownership of Operator …\nOnly the specific operators are allowed to operate the …\nTransaction is out of the tx range.\nPermissioned actions allowed by either specific accounts …\nType representing the runtime ID.\nTypes of runtime pallet domains currently supports\nHeader of bundle.\nStake weight in the domain bundle election.\nHolds all the currently staked funds to an Operator.\nStaking specific hold identifier\nType that holds the transfers(in/out) for a given chain.\nFailed to decode the opaque extrinsic.\nChains that are allowed to open channel with this chain.\nCompute and Domain storage fees are shared across …\nCompute and Domain storage fees are shared across …\nBlock hash of the confirmed domain block.\nBlock number of the confirmed domain block.\nReturn the bundle body size in bytes\nThe Merkle root of all new extrinsics included in this …\nBurned balances on domain chain\nCalculates the max bundle weight and size\nRewards for the chain.\nClaims a rejected transfer between chains.\nConfirms a transfer between chains.\nThe block hash corresponding to <code>consensus_block_number</code>.\nThe block hash corresponding to <code>consensus_block_number</code>.\nTODO: this field is only used in the bundle equivocation …\nA pointer to the consensus block index which contains all …\nA pointer to the consensus block index which contains all …\nReturn the consensus chain byte fee that will used to …\nThe consensus chain storage fee\nAccount info on frame_system on Domains\nReturns the current best number of the domain.\nExtrinsic root field of the header of domain block …\nExtrinsic root field of the header of domain block …\nThe block hash corresponding to <code>domain_block_number</code>.\nThe block hash corresponding to <code>domain_block_number</code>.\nReturns the domain block limit of the given domain.\nThe index of the current domain block that forms the basis …\nThe index of the current domain block that forms the basis …\nReturns the domain bundle limit of the given domain.\nCalled in the next block initialisation if there was a …\nThe domain execution fee including the storage and compute …\nReturns the domain_id of this bundle.\nDomain id.\nReturns the domain instance data for given <code>domain_id</code>.\nReturns the current epoch and the next epoch operators of …\nReturns the WASM bundle for given <code>domain_id</code>.\nReturn domain sudo call.\nTotal issuance storage for Domains.\nReturns the current Tx range for the given domain Id.\nThe total (estimated) weight of all extrinsics in the …\nReturns the execution receipt\nList of storage roots collected during the domain block …\nList of storage roots collected during the domain block …\nThe Merkle root of the execution trace for the current …\nThe Merkle root of the execution trace for the current …\nExtract bundle from the extrinsic if the extrinsic is …\nExtract the execution receipt stored successfully from the …\nExtract the bundles stored successfully from the given …\nThe accompanying extrinsics.\nThe accompanying extrinsics.\nReturn the <code>bundle_extrinsics_root</code>\nThe Merkle root of all new extrinsics included in this …\nExtrinsic root of the domain block.\nGenerates a randomness seed for extrinsics shuffling.\nThe final state root for the current domain block …\nThe final state root for the current domain block …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nReturn the genesis state root if not pruned\nReturns the hash of this header.\nReturns the hash of this header.\nReturns the hash of this bundle.\nReturns the hash of this execution receipt.\nReturns the best execution chain number.\nUnsealed header.\nThe hash of the bundle header\nAll the bundles that being included in the consensus block.\nAll the bundles that being included in the consensus block.\nInitializes the domain balance\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConvert a bundle with generic extrinsic to a bundle with …\nConsumes <code>Bundle</code> to extract the execution receipt.\nReturn if the receipt is exist and pending to prune\nReturns true if the account is the domain owner.\nReturn if the domain runtime code is upgraded since <code>at</code>\nReturns true if the allow list is either <code>Anyone</code> or the …\nReturns the latest confirmed domain block number and hash\nThe max block size for the domain.\nThe max block weight for the domain.\nThe max bundle size for the domain.\nThe max bundle weight for the domain.\nCreates a <code>DomainId</code>.\nConstructs a new instance of <code>SealedBundleHeader</code>.\nReturns true if there are any ERs in the challenge period …\nNotes a transfer between chains. Balance on from_chain_id …\nReturns the block number of oldest unconfirmed execution …\nThis is a representation of actual Block Fees storage in …\nReturn the <code>operator_id</code>\nOperator index in the OperatorRegistry.\nGet operator id by signing key\nParent block hash of the confirmed domain block.\nThe hash of the ER for the last domain block.\nThe hash of the ER for the last domain block.\nReturns the hash of the inner unsealed header.\nProof of bundle producer election.\nThe PoT output for <code>slot_number</code>.\nReturn a reference of the execution receipt.\nExecution receipt that should extend the receipt chain or …\nReturns the execution receipt hash of the given domain and …\nReduces a given amount from the domain balance\nRejects a initiated transfer between chains.\nTotal transfers from this domain that were reverted.\nChains that are not allowed to open channel with this …\nReturns the runtime id for given <code>domain_id</code>.\nSealed bundle header.\nSealed bundle header.\nThe storage key of the <code>SelfDomainId</code> storage item in the …\nSignature of the bundle.\nChecks if the signer Id hash is within the tx range\nReturn the bundle size (include header and body) in bytes\nThe size of the bundle body in bytes.\nThe slot number.\nState root of the domain block.\nReturn the balance of the storage fund account\nSubmits the transaction bundle via an unsigned extrinsic.\nDigest storage key in frame_system. Unfortunately, the …\nReturns the current timestamp at given height.\nConverts the inner integer to little-endian bytes.\nReturns the total fees that was collected and burned on …\nList of transfers from this Domain to other chains\nList of transfers from this Domain to other chains\nTotal transfers that came into the domain.\nTotal transfers that went out of the domain.\nTotal transfers to this domain that were rejected.\nComputes the VRF hash.\nVRF signature.\nInvalid vrf proof.\nThreshold unsatisfied error.\nReturns the election threshold based on the operator stake …\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nGenerates a domain-specific vrf transcript from given …\nBase API that every domain runtime must implement.\nReturns the storage root after applying the extrinsic.\nReturns the block digest.\nThe accumulated transaction fee of all transactions …\nReturns the storage key for the <code>CollectedBlockFees</code> on …\nReturns the consumed weight of the block.\nChecks the validity of array of extrinsics + pre_dispatch …\nReturns an encoded extrinsic to set domain transaction …\nReturns an extrinsic to update chain allowlist.\nReturns an encoded extrinsic aiming to upgrade the runtime …\nReturns an encoded extrinsic to set timestamp.\nDecodes the domain specific extrinsic from the opaque …\nExtracts the optional signer per extrinsic.\nReturns extrinsic Era if present.\nReturns the extrinsic weight.\nReturns the storage root after initializing the block.\nReturns the intermediate storage roots in an encoded form.\nReturns true if the extrinsic is an inherent extrinsic.\nReturns the transfers for this domain in the block.\nReturns the storage key for the Transfers on Domain.\nShuffles the extrinsics in a deterministic way.\nMerkle proof using <code>Blake2b256Algorithm</code>.\nMerkle tree using <code>Blake2b256Algorithm</code>.\nMerke proof based Witness.\nConstructs a merkle tree from given authorities.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nIndex of the leaf the proof is for.\nNumber of leaves in the original tree.\nMerkle proof in bytes.\nFailed to decode value.\nEmits when the given storage proof is invalid.\nValue doesn’t exist in the Db for the given key.\nType that provides utilities to generate the storage proof.\nType that provides utilities to verify the storage proof.\nStorage proof contains unused nodes after reading the …\nVerification error.\nConstructs the storage key from a given enumerated index.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGenerate storage proof for given index from the trie …\nReturns the value against a given key. Note: Storage proof …\nExtracts the value against a given key and returns a …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRaw storage content for genesis block\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nConstruct <code>RawGenesis</code> from a given storage NOTE: This …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConvert <code>RawGenesis</code> to storage, the opposite of <code>from_storage</code>\nThis is a modified version of trie root that takes trie …")