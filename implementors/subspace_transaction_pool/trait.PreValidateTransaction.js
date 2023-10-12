(function() {var implementors = {
"subspace_service":[["impl&lt;Block, Client, Verifier&gt; PreValidateTransaction for <a class=\"struct\" href=\"subspace_service/tx_pre_validator/struct.ConsensusChainTxPreValidator.html\" title=\"struct subspace_service::tx_pre_validator::ConsensusChainTxPreValidator\">ConsensusChainTxPreValidator</a>&lt;Block, Client, Verifier&gt;<span class=\"where fmt-newline\">where\n    Block: BlockT,\n    Client: ProvideRuntimeApi&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    Client::Api: PreValidationObjectApi&lt;Block, BlockNumber, Hash&gt;,\n    Verifier: VerifyFraudProof&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + 'static,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()