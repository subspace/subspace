searchState.loadedDescShard("sp_consensus_subspace", 0, "Primitives for Subspace consensus.\nSubspace blockchain constants.\nAn equivocation proof for multiple block authorships on …\nA Subspace farmer identifier. Necessarily equivalent to …\nA Subspace farmer signature.\nA KZG extension.\nA Poof of space extension.\nProof of time checkpoints that were not seen before\nA Poof of time extension.\nNext slot input for proof of time evaluation\nProof of time parameters\nChange of parameters to apply to PoT chain\nSigned farmer vote.\nSubspace solution ranges used for challenges.\nAPI necessary for block authorship with Subspace.\nSubspace justification\nV0 of the farmer vote.\nV0 of the chain constants.\nInitial version of the parameters\nFarmer vote.\nWrapped proof of time output for the purposes of runtime …\nWrapped solution for the purposes of runtime interface.\nWrapped solution verification parameters for the purposes …\nNumber of slots between slot arrival and when …\nGet Subspace blockchain constants\nDepth <code>K</code> after which a block enters the recorded history.\nConsensus-related runtime interface\nSolution range in current block/era.\nDerive next slot input while taking parameters change into …\nPrivate implementation details of Subspace consensus …\nEntropy that should be injected at this time\nEra duration in blocks.\nReturns <code>Vec&lt;SegmentHeader&gt;</code> if a given extrinsic has them.\nThe first header involved in the equivocation.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nHash of the vote, used for signing and verifying signature.\nSize of the blockchain history\nInherents for Subspace consensus\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nVerifies the equivocation proof by making sure that: both …\nCheck if <code>farmer_public_key</code> is in block list (due to …\nChecks if the extrinsic is an inherent.\nHow many pieces one sector is supposed to contain (max)\nMinimum lifetime of a plotted sector, measured in archived …\nReturns <code>true</code> if justification must be archived, implies …\nCreate new instance.\nCreate new instance.\nCreate new instance.\nSolution range that will be used in the next block/era.\nGet next proof of time parameters change if any\nCommon traits and types that are useful for describing …\nReturns the authority id of the equivocator.\nProof of time parameters\nFraction of pieces from the “recent history” (…\nNumber of latest archived segments that are considered “…\nReturns root plot public key in case block authoring is …\nThe second header involved in the equivocation.\nSeed for this slot\nGet the segment commitment of records for specified …\nWhether solution range adjustment is enabled.\nSignature.\nSlot at which vote was created.\nThe slot at which the equivocation happened.\nSlot\nAt which slot change of parameters takes effect\nThe slot duration in milliseconds.\nNumber of iterations for proof of time per slot, …\nSlot iterations for this slot\nNew number of slot iterations\nSlot probability.\nSolution contained within.\nSolution ranges.\nSubmits an unsigned extrinsic to report an equivocation. …\nSubmit farmer vote vote that is essentially a header with …\nTry to decode Subspace justification from generic …\nFarmer vote.\nVoting solution range in current block/era.\nVoting solution range that will be used in the next …\nNumber of slots between slot arrival and when …\nDepth <code>K</code> after which a block enters the recorded history.\nEra duration in blocks.\nMinimum lifetime of a plotted sector, measured in archived …\nFraction of pieces from the “recent history” (…\nNumber of latest archived segments that are considered “…\nThe slot duration in milliseconds.\nSlot probability.\nOptional next scheduled change of parameters\nNumber of iterations for proof of time per slot, …\nProof of time checkpoints from after future proof of …\nProof of time seed, the input for computing checkpoints\nFuture proof of time\nHeight at which vote was created.\nHash of the block on top of which vote was created.\nProof of time for this slot\nSlot at which vote was created.\nSolution (includes PoR).\nProvides implementations for the extern host functions.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nVerify whether <code>proof_of_time</code> is valid at specified <code>slot</code> if …\nVerify whether solution is valid, returns solution …\nA digest item which is usable with Subspace consensus.\nGeneric consensus\nParams used to derive the next solution range.\nDuplicate Subspace digests\nEnable solution range adjustment and override solution …\nDigest error\nVarious kinds of digest types used in errors\nFailed to decode Subspace digest\nSubspace digest missing\nError when deriving next digests\nError when verifying next digests\nType that holds the parameters to derive and verify next …\nNext solution range\nChange of parameters to apply to PoT chain\nNumber of iterations for proof of time per slot\nA Subspace pre-runtime digest. This contains all data …\nPre-digest\nProof of time information in pre-digest\nRoot plot public key was updated\nSeal (signature)\nSegment commitment\nSolution range\nDigest items extracted from a header into convenient form\nInitial version of the pre-digest\nInitial version of proof of time information\nIf this item is a Subspace Enable solution range …\nIf this item is a Subspace next solution range, return it.\nIf this item is a Subspace proof of time change of …\nIf this item is a Subspace proof of time slot iterations, …\nIf this item is a Subspace update of root plot public key, …\nIf this item is a Subspace segment commitment, return it.\nIf this item is a Subspace solution range, return it.\nIf this item is an Subspace pre-digest, return it.\nIf this item is a Subspace signature, return the signature.\nCurrent slot of the block.\nCurrent solution range of the block.\nDerives next solution range if era duration interval has …\nConstruct digest item than indicates enabling of solution …\nEnable solution range adjustment and Override solution …\nEra duration of the chain.\nEra duration at which solution range is updated.\nSlot at which era has begun.\nCurrent Era start slot.\nExtract the Subspace pre digest from the given header. …\nExtract the Subspace global randomness from the given …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nFuture proof of time\nDigests present in the header that corresponds to number …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nSolution range override that should be used instead of …\nNext Solution range override. If the digest logs indicate …\nRoot plot public key. Value is updated when digest items …\nConstruct a digest item which contains next solution range.\nNext solution range\nCurrent number of the block.\nHeader number for which we are verifying the digests.\nProof of time information\nChange of parameters to apply to PoT chain\nChange of parameters to apply to PoT chain\nNumber of iterations for proof of time per slot, …\nNumber of iterations for proof of time per slot, …\nPre-runtime digest\nProof of time for this slot\nConstruct digest item that indicates update of root plot …\nRoot plot public key was updated\nConstruct a digest item which contains segment commitment.\nSegment commitments\nFlag to check if the next solution range should be …\nShould the solution range be adjusted on era change. If …\nSignature (seal) if present\nSlot\nSlot probability at which a block is produced.\nSlot probability.\nSolution (includes PoR)\nConstruct a digest item which contains a solution range.\nSolution range\nConstruct a digest item which contains a Subspace …\nConstruct a digest item which contains a Subspace seal.\nDerives and verifies next digest items based on their …\nProof of time information\nSlot\nSolution (includes PoR)\nFuture proof of time\nProof of time for this slot\nThe Subspace inherent identifier.\nList of segment headers is not correct.\nProvides the segment headers inherent data for Subspace.\nErrors that can occur while checking segment headers.\nThe type of the Subspace inherent data.\nList of segment headers is not present.\nAuxiliary trait to extract Subspace inherent data.\nReturns the <code>data</code> of this inherent data provider.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate new inherent data provider from the given …\nReplace Subspace inherent data.\nSegment headers expected to be included in the block.\nGet Subspace inherent data.\nList of segment headers contained within proposed block.\nExpected list of segment headers according to node’s …\nThe report has already been submitted.\nIdentifier which is unique for this kind of an offence.\nThe kind of an offence, is a byte string representing some …\nA trait implemented by an offence report.\nA details about an offending authority for a particular …\nErrors that may happen on offence reports.\nA trait to take action on an offence.\nOther error has happened.\nA trait for decoupling offence reporters from the actual …\nA type that represents a point in time on an abstract …\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns true iff all of the given offenders have been …\nThe offending authority id\nThe list of all offenders involved in this incident.\nA handler for an offence of a particular kind.\nReport an <code>offence</code> and reward given <code>reporters</code>.\nA point in time when this offence happened.")