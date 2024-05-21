searchState.loadedDescShard("sc_consensus_subspace", 0, "<code>sc-consensus-subspace</code> is the core of Subspace consensus …\nState that must be shared between various consensus …\nGet stream with notifications about archived segment …\nConsensus archiver responsible for archival of blockchain …\nSchema for Subspace block weight in the aux-db.\nBlock import for Subspace, which includes stateful …\nGet stream with notifications about each imported block …\nSubspace chain constants.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nAccess KZG instance\nCreate new instance.\nGet stream with notifications about new slot arrival with …\nUtility module for handling Subspace client notifications.\nA stream with notifications about headers that need to be …\nSlot worker drives block and vote production based on …\nStateless and parallelized block verification that happens …\nNotification with block header hash that needs to be …\nPersistent storage of segment headers.\nSender that signified the fact of receiving archived …\nAdd segment headers.\nArchived segment.\nCrate an archiver task that will listen for importing …\nSymmetrical to <code>encode_block()</code>, used to decode previously …\nEncode block for archiving purposes.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a single segment header\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns last observed segment index\nCreate new instance\nDerive genesis segment on demand, returns <code>Ok(None)</code> in case …\nGet segment headers that are expected to be included at …\nBad reward signature\nNotification with number of the block that is about to be …\nCheck inherents error\nUnhandled check inherents error\nClient error\nCreate inherents error.\nDifferent segment commitment found\nError during digest item extraction\nErrors encountered by the Subspace authorship task.\nFarmer in block list\nGenesis block unavailable. Cannot import\nHeader has a bad seal\nHeader is unsealed\nInner block import error\nInvalid audit chunk offset\nInvalid chunk witness\nInvalid history size\nPiece verification failed\nPiece verification failed\nInvalid proof of space\nInvalid proof of time\nInvalid set of segment headers\nBlock has invalid associated solution range\nInvalid Subspace justification\nInvalid Subspace justification contents\nMissing Subspace justification\nNo block weight for parent header\nOnly root plot public key is allowed\nSolution is outside of solution range\nParent unavailable. Cannot import\nRuntime Api error.\nSector expired\nSegment commitment not found\nSegment header not found\nStored segment header extrinsic was not found\nSlot number must increase\nA block-import handler for Subspace.\nSender for pausing the block import when operator is not …\nBlock number\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nProduce a Subspace block-import object to be used later on …\nCurrent history size\nExpiration history size\nHalf of solution range\nHow many pieces one sector is supposed to contain (max)\nIndex of the piece that failed verification\nTime slot\nTime slot\nSolution distance\nThe receiving half of the Subspace notification channel.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nSubscribe to a channel through which notifications are …\nInformation about new slot that just arrived\nNew slot notification with slot information and sender for …\nNotification with a hash that needs to be signed to …\nSubspace slot worker responsible for block and vote …\nParameters for <code>SubspaceSlotWorker</code>\nSubspace sync oracle that takes into account force …\nStrategy and parameters for backing off block production.\nThe underlying block-import object to supply our produced …\nThe proportion of the slot dedicated to proposing.\nThe client to use\nThe environment we are producing blocks for.\nForce authoring of blocks even if we are offline\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nHash to be signed.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nHook into the sync module to control the justification …\nThe maximum proportion of the slot dedicated to proposing …\nCreate new Subspace slot worker\nCreate new instance\nNew slot information.\nThe offchain transaction pool factory.\nProof of time verifier\nThe PoT output for <code>slot</code>\nPublic key of the plot identity that should create …\nPersistent storage of segment headers\nSender that can be used to send signature for the header.\nSlot\nAcceptable solution range for block authoring\nSender that can be used to send solutions for the slot.\nThe source of timestamps for relative slots\nA sync oracle\nHandle use to report telemetries.\nAcceptable solution range for voting\nBad reward signature\nHeader has a bad seal\nHeader is unsealed\nInvalid proof of time\nInvalid Subspace justification\nInvalid Subspace justification contents\nMissing Subspace justification\nA verifier for Subspace blocks.\nOptions for Subspace block verifier\nErrors encountered by the Subspace verification task.\nVerification error\nSubspace chain constants\nSubstrate client\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether this node is authoring blocks\nKzg instance\nCreate new instance\nThe offchain transaction pool factory.\nProof of time verifier\nContext for reward signing\nChain selection rule\nApproximate target block number for syncing purposes\nTelemetry")