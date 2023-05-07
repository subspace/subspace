(function() {var implementors = {
"domain_client_executor":[["impl&lt;Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, ParentChain&gt; GossipMessageHandler&lt;PBlock, Block&gt; for <a class=\"struct\" href=\"domain_client_executor/struct.CoreGossipMessageValidator.html\" title=\"struct domain_client_executor::CoreGossipMessageValidator\">CoreGossipMessageValidator</a>&lt;Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, ParentChain&gt;<span class=\"where fmt-newline\">where\n    Block: BlockT,\n    SBlock: BlockT,\n    PBlock: BlockT,\n    Block::Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;H256&gt;,\n    Client: HeaderBackend&lt;Block&gt; + BlockBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + AuxStore + ProofProvider&lt;Block&gt; + 'static,\n    Client::Api: DomainCoreApi&lt;Block&gt; + BlockBuilder&lt;Block&gt; + ApiExt&lt;Block, StateBackend = StateBackendFor&lt;Backend, Block&gt;&gt;,\n    SClient: HeaderBackend&lt;SBlock&gt; + ProvideRuntimeApi&lt;SBlock&gt; + 'static,\n    SClient::Api: SystemDomainApi&lt;SBlock, NumberFor&lt;PBlock&gt;, PBlock::Hash&gt;,\n    PClient: HeaderBackend&lt;PBlock&gt; + 'static,\n    Backend: Backend&lt;Block&gt; + 'static,\n    &lt;&lt;Backend as Backend&lt;Block&gt;&gt;::State as StateBackend&lt;HashFor&lt;Block&gt;&gt;&gt;::Transaction: HashDBT&lt;HashFor&lt;Block&gt;, DBValue&gt;,\n    TransactionPool: TransactionPool&lt;Block = Block&gt; + 'static,\n    E: CodeExecutor,\n    ParentChain: ParentChainInterface&lt;SBlock&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + 'static,</span>"],["impl&lt;Block, PBlock, Client, PClient, TransactionPool, Backend, E, ParentChain&gt; GossipMessageHandler&lt;PBlock, Block&gt; for <a class=\"struct\" href=\"domain_client_executor/struct.SystemGossipMessageValidator.html\" title=\"struct domain_client_executor::SystemGossipMessageValidator\">SystemGossipMessageValidator</a>&lt;Block, PBlock, Client, PClient, TransactionPool, Backend, E, ParentChain&gt;<span class=\"where fmt-newline\">where\n    Block: BlockT,\n    PBlock: BlockT,\n    Block::Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;H256&gt;,\n    Client: HeaderBackend&lt;Block&gt; + BlockBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + AuxStore + ProofProvider&lt;Block&gt; + 'static,\n    Client::Api: DomainCoreApi&lt;Block&gt; + SystemDomainApi&lt;Block, NumberFor&lt;PBlock&gt;, PBlock::Hash&gt; + BlockBuilder&lt;Block&gt; + ApiExt&lt;Block, StateBackend = StateBackendFor&lt;Backend, Block&gt;&gt;,\n    Backend: Backend&lt;Block&gt; + 'static,\n    PClient: HeaderBackend&lt;PBlock&gt; + 'static,\n    &lt;&lt;Backend as Backend&lt;Block&gt;&gt;::State as StateBackend&lt;HashFor&lt;Block&gt;&gt;&gt;::Transaction: HashDBT&lt;HashFor&lt;Block&gt;, DBValue&gt;,\n    TransactionPool: TransactionPool&lt;Block = Block&gt; + 'static,\n    E: CodeExecutor,\n    ParentChain: ParentChainInterface&lt;PBlock&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + 'static,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()