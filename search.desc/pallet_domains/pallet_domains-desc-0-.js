searchState.loadedDescShard("pallet_domains", 0, "Pallet Domains\nBad/Invalid bundle equivocation fraud proof.\nInvalid signature on the bundle header.\nOperator submitted bad Execution receipt.\nOperator is not allowed to produce bundles in current …\nThe bad receipt already reported by a previous fraud proof\nThe targeted bad receipt not found which may already …\nBad/Invalid valid bundle fraud proof\nInvalid vrf signature in the proof of election.\nThe block slot\nBlock tree specific errors\nThe block tree pruning depth.\nOperator caused Bundle equivocation\nHow many block a bundle should still consider as valid …\nBundle storage fund specific errors\nA domain bundle was included.\nBundle weight exceeds the max bundle weight limit\nBundle size exceed the max bundle size limit in the domain …\nContains a variant per dispatchable extrinsic that this …\nThe genesis receipt is unchallengeable.\nConfiguration trait of this pallet.\nSame with <code>pallet_subspace::Config::ConfirmationDepthK</code>.\nThe consensus block hash used to verify ER, only store the …\nConsensus chain slot probability.\nCurrency type used by the domains for staking and other …\nThe descendants of the fraudulent ER is not pruned\nPost hook to notify accepted domain bundles in previous …\nDomain block hash type.\nThe domain header type.\nThe amount of fund to be locked up for the domain instance …\nDomain registry specific errors\nDelay before a domain runtime is upgraded.\nDomain tx range is adjusted after every …\nTransfers tracker.\nThis bundle duplicated with an already submitted bundle\nThe <code>Error</code> enum of this pallet.\nThe <code>Event</code> enum of this pallet\nA set of <code>BundleDigest</code> from all bundles that successfully …\nInvalid fraud proof.\nCan be used to configure the genesis state of this pallet.\nA variation of the Identifier used for holding the funds …\nInitial domain tx range value.\nInvalid fraud proof since block fees are not mismatched.\nOperator produced bad bundle.\nInvalid bundles fraud proof\nInvalid domain block hash fraud proof.\nCan not find the domain for given domain id.\nBundle with an invalid extrinsic root\nInvalid domain extrinsic fraud proof\nCan not find the operator for given operator id.\nInvalid proof of time in the proof of election\nInvalid state transition fraud proof\nInvalid fraud proof since transfers are not mismatched.\nThe maximum bundle per block limit for all domain.\nThe maximum block size limit for all domain.\nThe maximum block weight limit for all domain.\nThe maximum domain name length limit for all domain.\nUpper limit for total initial accounts domains\nThe maximum number of nominators for given operator.\nThe maximum number of pending staking operation that can …\nMinimum balance for each initial domain account\nMinimum nominator stake required to nominate and operator.\nMinimum operator stake required to become operator of a …\nMissing operator.\nType alias to <code>Pallet</code>, to be used by <code>construct_runtime</code>.\nShare price for the operator pool at the end of Domain …\nThe <code>Pallet</code> struct, the main type that implements traits …\nThe pallet-domains’s pallet id.\nParent receipt not found.\nPermissioned action is not allowed by the caller.\nRandomness source.\nAn invalid execution receipt found in the bundle.\nRuntime registry specific errors\nType representing the shares in the staking protocol.\nReason for slashing an operator\nThe bundle is built on a slot in the future\nThe bundle is built on a slot in the past\nDomain epoch transition interval\nMinimum number of blocks after which any finalized …\nStaking related errors.\nStaking epoch specific errors.\nThe Bundle is created too long ago.\nStarting EVM chain ID for evm runtimes.\nStorage fee interface used to deal with bundle storage fee\nFailed to pass the threshold check.\nTreasury account.\nPer-domain state for tx range calculation.\nUnable to calculate bundle limit\nUnexpected fraud proof.\nWeight information for extrinsics in this pallet.\nCompute and Domain storage fees are shared across …\nDomain block tree\nCalculates the new tx range based on the bundles produced …\nThe block hash corresponding to <code>consensus_block_number</code>.\nAn auto-generated getter for <code>ConsensusBlockHash</code>.\nA pointer to the consensus block index which contains all …\nAuto-generated docs-only module listing all defined …\nExtrinsic root field of the header of domain block …\nThe block hash corresponding to <code>domain_block_number</code>.\nReturns the domain block limit of the given domain.\nThe index of the current domain block that forms the basis …\nReturns the domain bundle limit of the given domain\nDomain registry for domains\nAn auto-generated getter for <code>DomainStakingSummary</code>.\nReturns the tx range for the domain.\nThe full ER for this block.\nList of storage roots collected during the domain block …\nThe Merkle root of the execution trace for the current …\nThe accompanying extrinsics.\nThe final state root for the current domain block …\nForce staking epoch transition for a given domain\nForce staking epoch transition for a given domain\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nReturns the best execution chain number.\nAll the bundles that being included in the consensus block.\nBlocks in the current adjustment interval.\nBundles in the current adjustment interval.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the latest confirmed domain block number for a …\nAn auto-generated getter for <code>LatestSubmittedER</code>.\nCreate a call with the variant <code>deregister_operator</code>.\nCreate a call with the variant …\nCreate a call with the variant <code>instantiate_domain</code>.\nCreate a call with the variant <code>nominate_operator</code>.\nCreate a call with the variant <code>register_domain_runtime</code>.\nCreate a call with the variant <code>register_operator</code>.\nCreate a call with the variant …\nCreate a call with the variant <code>submit_bundle</code>.\nCreate a call with the variant <code>submit_fraud_proof</code>.\nCreate a call with the variant <code>unlock_funds</code>.\nCreate a call with the variant <code>unlock_operator</code>.\nCreate a call with the variant …\nCreate a call with the variant <code>upgrade_domain_runtime</code>.\nCreate a call with the variant <code>withdraw_stake</code>.\nReturns if there are any ERs in the challenge period that …\nReturns the block number of the oldest existing …\nCalled when a bundle is added to the current block.\nA set of all operators who have committed to this ER …\nAn auto-generated getter for <code>OperatorSigningKey</code>.\nThe hash of the ER for the last domain block.\nRuntime registry for domains\nSealed bundle header.\nUpdate permissioned action allowed by storage by Sudo.\nUpdate permissioned action allowed by storage by Sudo.\nAuto-generated docs-only module listing all (public and …\nSubmits an unsigned extrinsic <code>Call::submit_bundle</code>.\nSubmits an unsigned extrinsic <code>Call::submit_fraud_proof</code>.\nList of transfers from this Domain to other chains\nCurrent tx range.\nUnlocks the first withdrawal given the unlocking period is …\nUnlocks the first withdrawal given the unlocking period is …\nUnlocks the operator given the unlocking period is …\nUnlocks the operator given the unlocking period is …\nExtrinsic to update domain’s operator allow list. Note:\nExtrinsic to update domain’s operator allow list. Note:\nAutogenerated weights for pallet_domains\nBlock tree specific errors\nThe full ER for this block.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nA set of all operators who have committed to this ER …\nWarning: Doc-Only\nForce staking epoch transition for a given domain\nWarning: Doc-Only\nWarning: Doc-Only\nWarning: Doc-Only\nWarning: Doc-Only\nUpdate permissioned action allowed by storage by Sudo.\nWarning: Doc-Only\nWarning: Doc-Only\nUnlocks the first withdrawal given the unlocking period is …\nUnlocks the operator given the unlocking period is …\nExtrinsic to update domain’s operator allow list. Note:\nWarning: Doc-Only\nWarning: Doc-Only\nDomain registry specific errors\nThe probability of successful bundle in a slot (active …\nThe consensus chain block number when the domain first …\nThe domain config.\nA user defined name for this domain, should be a …\nDomain runtime specific information.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nThe hash of the genesis execution receipt for this domain.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe max block size for this domain, may not exceed the …\nThe max block weight for this domain, may not exceed the …\nAllowed operators to operate for this domain.\nThe address of the domain creator, used to validate …\nA pointer to the <code>RuntimeRegistry</code> entry for this domain.\nThe expected number of bundles for a domain block, must be …\nDomain runtime specific information to create domain raw …\nRuntime specific errors\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAccumulate treasury funds temporarily until the funds are …\nThe domain block tree, map (<code>domain_id</code>, <code>domain_block_number</code>…\nMapping of block tree node hash to the node, each node …\nThe consensus block hash used to verify ER, only store the …\nList of all deposits for given Operator.\nThe domain registry\nWarning: Doc-Only\nWarning: Doc-Only\nA set of <code>BundleDigest</code> from all bundles that successfully …\nThe block number of the best domain block, increase by one …\nWhether the head receipt have extended in the current …\nThe head receipt number of each domain\nA mapping of <code>bundle_header_hash</code> -&gt; <code>bundle_author</code> for all …\nA temporary storage to hold any previous epoch details for …\nStorage to hold all the domain’s latest confirmed block.\nThe latest ER submitted by the operator for a given …\nStores the next domain id.\nStores the next evm chain id.\nWarning: Doc-Only\nStores the next runtime id.\nTracks the nominator count under given operator. This …\nShare price for the operator pool at the end of Domain …\nWarning: Doc-Only\nIndexes operator signing key against OperatorId.\nList of all registered operators and their configuration.\nTemporary hold of all the operators who decided to switch …\nA list operators who were slashed during the current epoch …\nThe pending staking operation count of the current epoch, …\nStorage for PermissionedActions for domain instantiation …\nWarning: Doc-Only\nWarning: Doc-Only\nBundles submitted successfully in current block.\nFraud proofs submitted successfully in current block.\nList of all withdrawals for a given operator.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWeights for pallet_domains using the Substrate node and …\nWeight functions needed for pallet_domains.\nStorage: <code>Domains::Operators</code> (r:200 w:100) Proof: …\nStorage: <code>Domains::OperatorIdOwner</code> (r:1 w:0) Proof: …\nStorage: <code>Domains::DomainStakingSummary</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::PendingSlashes</code> (r:1 w:1) Proof: …\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nStorage: <code>Domains::BlockTree</code> (r:1 w:1) Proof: …\nStorage: <code>Sudo::Key</code> (r:1 w:0) Proof: <code>Sudo::Key</code> (<code>max_values</code>: …\nCalls <code>U::from(self)</code>.\nStorage: <code>Domains::Operators</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::DomainStakingSummary</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::NextRuntimeId</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::PendingStakingOperationCount</code> (r:1 w:1) …\nStorage: <code>Domains::HeadReceiptNumber</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::HeadReceiptNumber</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::Operators</code> (r:1 w:0) Proof: …\nStorage: <code>Domains::Operators</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::DomainRegistry</code> (r:1 w:1) Proof: …\nStorage: <code>Domains::RuntimeRegistry</code> (r:1 w:0) Proof: …\nStorage: <code>Domains::Operators</code> (r:1 w:1) Proof: …")