(function() {var implementors = {
"sc_consensus_subspace":[["impl&lt;PosTable, Block, Client, E, SO, L, BS, AS&gt; <a class=\"trait\" href=\"sc_proof_of_time/trait.PotSlotWorker.html\" title=\"trait sc_proof_of_time::PotSlotWorker\">PotSlotWorker</a>&lt;Block&gt; for <a class=\"struct\" href=\"sc_consensus_subspace/slot_worker/struct.SubspaceSlotWorker.html\" title=\"struct sc_consensus_subspace::slot_worker::SubspaceSlotWorker\">SubspaceSlotWorker</a>&lt;PosTable, Block, Client, E, SO, L, BS, AS&gt;<div class=\"where\">where\n    Block: BlockT,\n    Client: HeaderBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt;,\n    Client::Api: <a class=\"trait\" href=\"sp_consensus_subspace/trait.SubspaceApi.html\" title=\"trait sp_consensus_subspace::SubspaceApi\">SubspaceApi</a>&lt;Block, <a class=\"type\" href=\"sp_consensus_subspace/type.FarmerPublicKey.html\" title=\"type sp_consensus_subspace::FarmerPublicKey\">FarmerPublicKey</a>&gt;,\n    SO: SyncOracle + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,</div>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()