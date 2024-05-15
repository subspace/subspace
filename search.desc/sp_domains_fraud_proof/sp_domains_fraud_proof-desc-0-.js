searchState.loadedDescShard("sp_domains_fraud_proof", 0, "Subspace fraud proof primitives for consensus chain.\nBlock randomness at a given consensus block hash.\nBlock randomness fetched from consensus state at a …\nRequest to check extrinsics in single context\nResult of check extrinsics in single context\nDomain <code>set_consensus_chain_byte_fee</code> extrinsic using the …\nEncoded domain <code>set_consensus_chain_byte_fee</code> extrinsic …\nThe body of domain bundle included in a given consensus …\nDomain block body fetch from a specific consensus block …\nType that maybe holds an encoded update domain chain …\nEncoded domain update_chain_allowlist extrinsic if there …\nDomains <code>update_domain_chain_allowlist</code> extrinsic at a given …\nRequest to get Domain election params.\nDomain’s total stake at a given Consensus hash.\nThe domain runtime code\nThe domain runtime code\nDomain set_code extrinsic if there is a runtime upgrade at …\nEncoded domain set_code extrinsic if there is a runtime …\nDomain timestamp extrinsic using the timestamp at a given …\nEncoded domain timestamp extrinsic using the timestamp …\nHolds an encoded set_code extrinsic with an upgraded …\nHolds an encoded extrinsic with updates.\nRequest to check if the domain extrinsic is decodable or …\nIf the domain extrinsic is decodable or not.\nAPI necessary for fraud proof.\nDomains fraud proof host function\nTrait to query and verify Domains Fraud proof.\nTrait Impl to query and verify Domains Fraud proof.\nRequest type to fetch required verification information …\nResponse holds required verification information for fraud …\nProvides implementations for the extern host functions.\nRequest to check if particular extrinsic is an inherent …\nIf the particular extrinsic provided is either inherent or …\nCustom invalid validity code for the extrinsics in …\nNo runtime upgrade.\nNo updates\nRequest to get Operator stake.\nOperators Stake at a given Consensus hash.\nType that maybe holds an encoded set_code extrinsic with …\nRequest to fetch a specific storage key\nResult of the storage key request\nType that specifies the request of storage keys\nDomain’s transfers storage key\nRequest to check if particular extrinsic is in range for …\nIf particular extrinsic is in range for (domain, bundle) …\nRequest to check if the XDM is valid\nIf the particular xdm extrinsic is valid or not. Returns …\nModule to check bundle equivocation and produce the …\nDerive the bundle digest for the given bundle body.\nDerive the bundle digest for the given bundle body.\nCheck the execution proof\nThis module provides the feature of generating and …\nExtract the fraud proof handled successfully from the …\nDomain fraud proof related runtime interface\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nReturns the required verification info for the runtime to …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a new instance of <code>FraudProofExtension</code>.\nSubmit the fraud proof via an unsigned extrinsic.\nIndex of the bundle in which the extrinsic exists\nDomain block hash from ER\nDomain block number from ER\nDomain block state root from ER\nExtrinsics which we want to check in single context\nExtrinsic for which we need to check the range\nExtrinsic for which we need to if it is inherent or not.\nExtrinsic for which we need to if it is decodable or not.\nEncoded XDM extrinsic that needs to be validated.\nStorage proof for the keys used in validating the extrinsic\nContains the error value\nContains the success value\nChecks if the header is an equivocation and returns the …\nCreates storage proof for verifying an execution without …\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nConstructs a new instance of <code>ExecutionProver</code>.\nReturns a storage proof which can be used to reconstruct a …\nExecutes some extrinsic.\nMismatch type possible for ApplyExtrinsic execution phase\nFailed to pass the execution proof check.\nRepresents a bundle equivocation proof. An equivocation …\nBundle with requested index not found in execution receipt\nRuntime api error.\nHash of the consensus block being challenged not found.\nDecode error.\nDomain state root not found.\nA phase of a block’s execution, carrying necessary …\nFailed to check if a given extrinsic is decodable or not.\nFailed to check extrinsics in single context\nFailed to check if a given extrinsic is inherent or not.\nFailed to derive bundle digest\nFailed to derive consensus chain byte fee extrinsic\nFailed to derive domain chain allowlist extrinsic\nFailed to derive domain set code extrinsic\nFailed to derive domain timestamp extrinsic\nFailed to get block randomness\nFailed to get the bundle body\nTx range host function did not return response (returned …\nFailed to check if a given extrinsic is inherent or not.\nExecutes the <code>finalize_block</code> hook.\nMismatch type possible for FinalizBlock execution phase\nFraud proof.\nFailed to decode the header produced by <code>finalize_block</code>.\nRepresents an invalid transaction proof.\nExecutes the <code>initialize_block</code> hook.\nFailed to decode the return value of <code>initialize_block</code> and …\nRepresents an invalid block fees proof.\nInvalid bundle digest\nInvalid bundle equivocation fraud proof.\nRepresents an invalid domain block hash fraud proof.\nRepresents an Invalid domain extrinsics root proof with …\nThe fraud proof prove nothing invalid\nProves an invalid state transition by challenging the …\nInvalid storage proof.\nRepresents an invalid transaction proof.\nRepresents an invalid transfers proof.\nRuntime api error.\nFail to get runtime code.\nCan not find signer from the domain extrinsic.\nState not found in the storage proof.\nFailed to decode the storage root produced by verifying …\nThe target valid bundle not found from the target bad …\nInvalid bundle entry in bad receipt was expected to be …\nRepresents a valid bundle index and all the extrinsics …\nFraud proof for the valid bundles in …\nTransaction validity check passes.\nError type of fraud proof verification on consensus node.\nHash of the bad receipt in which an invalid trace occurred.\nHash of the bad receipt this fraud proof targeted\nHash of the bad receipt this fraud proof targeted\nHash of the bad receipt this fraud proof targeted\nHash of the bad receipt this fraud proof targeted\nHash of the bad receipt this fraud proof targeted\nHash of the bad receipt this fraud proof targeted\nThe targetted bad receipt\n<code>Vec&lt;(tx_signer, tx_hash)&gt;</code> of all extrinsics\nIndex of this bundle in the original list of bundles in …\nThe index of the targetted bundle\nReturns the post state root for the given execution result.\nDigests storage proof that is used to derive Domain block …\nHash of the domain block corresponding to <code>block_number</code>.\nNumber of the block at which the invalid transaction …\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nThe id of the domain this fraud proof targeted\nReturns the method for generating the proof.\nExecution phase.\nThe first header involved in the equivocation.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nGet a reference to the inner from the outer.\nReturns the hash of this bundle equivocation proof.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns true if execution phase refers to mismatch between …\nProof recorded during the computation.\nThe second header involved in the equivocation.\nThe slot at which the equivocation happened.\nStorage witness needed for verifying this proof.\nStorage witness needed for verifying this proof.\nStorage witness needed for verifying this proof.\nDigest storage key in frame_system. Unfortunately, the …\nValid Bundle digests\nHash of the bad receipt this fraud proof targeted\nId of the domain this fraud proof targeted\nProvides implementations for the extern host functions.\nDerive the bundle digest for the given bundle body.\nCheck the execution proof with also included domain block …\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nReturns required fraud proof verification information to …\nCalls <code>U::from(self)</code>.\nBundle signature is invalid.\nBundle slot mismatch.\nFailed to get domain total stake.\nFailed to get operator stake.\nRepresents error for invalid bundle equivocation proof.\nInvalid Proof of election.\nMismatched operatorId and Domain.\nSame bundle hash.\nReturns the argument unchanged.\nGet a mutable reference to the inner from the outer.\nGet a reference to the inner from the outer.\nCalls <code>U::from(self)</code>.\nVerifies Bundle equivocation fraud proof.\nVerifies invalid block fees fraud proof.\nVerifies invalid domain block hash fraud proof.\nVerifies invalid domain extrinsic root fraud proof.\nVerifies invalid state transition fraud proof.\nVerifies invalid transfers fraud proof.\nVerifies valid bundle fraud proof.")