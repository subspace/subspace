(function() {var type_impls = {
"domain_test_service":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-DomainNode%3CRuntime,+RuntimeApi,+AccountId%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#122-397\">source</a><a href=\"#impl-DomainNode%3CRuntime,+RuntimeApi,+AccountId%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Runtime, RuntimeApi, AccountId&gt; <a class=\"struct\" href=\"domain_test_service/domain/struct.DomainNode.html\" title=\"struct domain_test_service::domain::DomainNode\">DomainNode</a>&lt;Runtime, RuntimeApi, AccountId&gt;<div class=\"where\">where\n    Runtime: Config&lt;Hash = H256&gt; + Config + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    Runtime::RuntimeCall: Dispatchable&lt;Info = DispatchInfo, PostInfo = PostDispatchInfo&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    &lt;&lt;Runtime as Config&gt;::OnChargeTransaction as OnChargeTransaction&lt;Runtime&gt;&gt;::Balance: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>&gt; + FixedPointOperand,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;BlockNumberFor&lt;Runtime&gt;&gt;,\n    RuntimeApi: ConstructRuntimeApi&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, <a class=\"type\" href=\"domain_service/type.FullClient.html\" title=\"type domain_service::FullClient\">FullClient</a>&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, RuntimeApi&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + 'static,\n    RuntimeApi::RuntimeApi: ApiExt&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + Metadata&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + BlockBuilder&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + OffchainWorkerApi&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + SessionKeys&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + <a class=\"trait\" href=\"sp_domains/core_api/trait.DomainCoreApi.html\" title=\"trait sp_domains::core_api::DomainCoreApi\">DomainCoreApi</a>&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + TaggedTransactionQueue&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt; + AccountNonceApi&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, AccountId, <a class=\"type\" href=\"subspace_runtime_primitives/type.Nonce.html\" title=\"type subspace_runtime_primitives::Nonce\">Nonce</a>&gt; + TransactionPaymentRuntimeApi&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, <a class=\"type\" href=\"domain_runtime_primitives/type.Balance.html\" title=\"type domain_runtime_primitives::Balance\">Balance</a>&gt; + <a class=\"trait\" href=\"sp_messenger/trait.MessengerApi.html\" title=\"trait sp_messenger::MessengerApi\">MessengerApi</a>&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, NumberFor&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt;&gt; + <a class=\"trait\" href=\"sp_messenger/trait.RelayerApi.html\" title=\"trait sp_messenger::RelayerApi\">RelayerApi</a>&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, NumberFor&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt;, &lt;<a class=\"type\" href=\"subspace_runtime_primitives/opaque/type.Block.html\" title=\"type subspace_runtime_primitives::opaque::Block\">Block</a> as BlockT&gt;::Hash&gt; + <a class=\"trait\" href=\"domain_test_primitives/trait.OnchainStateApi.html\" title=\"trait domain_test_primitives::OnchainStateApi\">OnchainStateApi</a>&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>, AccountId, <a class=\"type\" href=\"domain_runtime_primitives/type.Balance.html\" title=\"type domain_runtime_primitives::Balance\">Balance</a>&gt; + EthereumRuntimeRPCApi&lt;<a class=\"type\" href=\"domain_runtime_primitives/opaque/type.Block.html\" title=\"type domain_runtime_primitives::opaque::Block\">Block</a>&gt;,\n    AccountId: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.195/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a> + Encode + Decode + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html\" title=\"trait core::fmt::Display\">Display</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/str/traits/trait.FromStr.html\" title=\"trait core::str::traits::FromStr\">FromStr</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"domain_test_service/domain/trait.FromKeyring.html\" title=\"trait domain_test_service::domain::FromKeyring\">FromKeyring</a> + 'static,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.wait_for_blocks\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#288-290\">source</a><h4 class=\"code-header\">pub fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.wait_for_blocks\" class=\"fn\">wait_for_blocks</a>(&amp;self, count: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>) -&gt; impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/future/future/trait.Future.html\" title=\"trait core::future::future::Future\">Future</a>&lt;Output = <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Wait for <code>count</code> blocks to be imported in the node and then exit. This function will not\nreturn if no blocks are ever created, thus you should restrict the maximum amount of time of\nthe test execution.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.account_nonce\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#293-301\">source</a><h4 class=\"code-header\">pub fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.account_nonce\" class=\"fn\">account_nonce</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h4></section></summary><div class=\"docblock\"><p>Get the nonce of the node account</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.send_system_remark\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#304-312\">source</a><h4 class=\"code-header\">pub async fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.send_system_remark\" class=\"fn\">send_system_remark</a>(&amp;mut self)</h4></section></summary><div class=\"docblock\"><p>Sends an system.remark extrinsic to the pool.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.construct_and_send_extrinsic\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#315-321\">source</a><h4 class=\"code-header\">pub async fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.construct_and_send_extrinsic\" class=\"fn\">construct_and_send_extrinsic</a>(\n    &amp;mut self,\n    function: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;&lt;Runtime as Config&gt;::RuntimeCall&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;RpcTransactionOutput, RpcTransactionError&gt;</h4></section></summary><div class=\"docblock\"><p>Construct an extrinsic with the current nonce of the node account and send it to this node.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.construct_and_send_extrinsic_with\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#324-339\">source</a><h4 class=\"code-header\">pub async fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.construct_and_send_extrinsic_with\" class=\"fn\">construct_and_send_extrinsic_with</a>(\n    &amp;self,\n    nonce: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>,\n    tip: &lt;&lt;Runtime as Config&gt;::OnChargeTransaction as OnChargeTransaction&lt;Runtime&gt;&gt;::Balance,\n    function: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;&lt;Runtime as Config&gt;::RuntimeCall&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;RpcTransactionOutput, RpcTransactionError&gt;</h4></section></summary><div class=\"docblock\"><p>Construct an extrinsic with the given nonce and tip for the node account and send it to this node.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.construct_extrinsic\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#342-355\">source</a><h4 class=\"code-header\">pub fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.construct_extrinsic\" class=\"fn\">construct_extrinsic</a>(\n    &amp;mut self,\n    nonce: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>,\n    function: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;&lt;Runtime as Config&gt;::RuntimeCall&gt;\n) -&gt; UncheckedExtrinsic&lt;<a class=\"type\" href=\"evm_domain_test_runtime/type.Address.html\" title=\"type evm_domain_test_runtime::Address\">Address</a>, &lt;Runtime as Config&gt;::RuntimeCall, <a class=\"type\" href=\"evm_domain_test_runtime/type.Signature.html\" title=\"type evm_domain_test_runtime::Signature\">Signature</a>, (CheckNonZeroSender&lt;Runtime&gt;, CheckSpecVersion&lt;Runtime&gt;, CheckTxVersion&lt;Runtime&gt;, CheckGenesis&lt;Runtime&gt;, CheckMortality&lt;Runtime&gt;, CheckNonce&lt;Runtime&gt;, CheckWeight&lt;Runtime&gt;, ChargeTransactionPayment&lt;Runtime&gt;)&gt;</h4></section></summary><div class=\"docblock\"><p>Construct an extrinsic.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.construct_extrinsic_with_tip\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#358-372\">source</a><h4 class=\"code-header\">pub fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.construct_extrinsic_with_tip\" class=\"fn\">construct_extrinsic_with_tip</a>(\n    &amp;mut self,\n    nonce: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>,\n    tip: &lt;&lt;Runtime as Config&gt;::OnChargeTransaction as OnChargeTransaction&lt;Runtime&gt;&gt;::Balance,\n    function: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;&lt;Runtime as Config&gt;::RuntimeCall&gt;\n) -&gt; UncheckedExtrinsic&lt;<a class=\"type\" href=\"evm_domain_test_runtime/type.Address.html\" title=\"type evm_domain_test_runtime::Address\">Address</a>, &lt;Runtime as Config&gt;::RuntimeCall, <a class=\"type\" href=\"evm_domain_test_runtime/type.Signature.html\" title=\"type evm_domain_test_runtime::Signature\">Signature</a>, (CheckNonZeroSender&lt;Runtime&gt;, CheckSpecVersion&lt;Runtime&gt;, CheckTxVersion&lt;Runtime&gt;, CheckGenesis&lt;Runtime&gt;, CheckMortality&lt;Runtime&gt;, CheckNonce&lt;Runtime&gt;, CheckWeight&lt;Runtime&gt;, ChargeTransactionPayment&lt;Runtime&gt;)&gt;</h4></section></summary><div class=\"docblock\"><p>Construct an extrinsic with the given transaction tip.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.send_extrinsic\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#375-380\">source</a><h4 class=\"code-header\">pub async fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.send_extrinsic\" class=\"fn\">send_extrinsic</a>(\n    &amp;self,\n    extrinsic: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;OpaqueExtrinsic&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;RpcTransactionOutput, RpcTransactionError&gt;</h4></section></summary><div class=\"docblock\"><p>Send an extrinsic to this node.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.free_balance\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#383-388\">source</a><h4 class=\"code-header\">pub fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.free_balance\" class=\"fn\">free_balance</a>(&amp;self, account_id: AccountId) -&gt; <a class=\"type\" href=\"domain_runtime_primitives/type.Balance.html\" title=\"type domain_runtime_primitives::Balance\">Balance</a></h4></section></summary><div class=\"docblock\"><p>Get the free balance of the given account</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get_open_channel_for_chain\" class=\"method\"><a class=\"src rightside\" href=\"src/domain_test_service/domain.rs.html#391-396\">source</a><h4 class=\"code-header\">pub fn <a href=\"domain_test_service/domain/struct.DomainNode.html#tymethod.get_open_channel_for_chain\" class=\"fn\">get_open_channel_for_chain</a>(&amp;self, chain_id: <a class=\"enum\" href=\"sp_domains/enum.ChainId.html\" title=\"enum sp_domains::ChainId\">ChainId</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"type\" href=\"sp_messenger/messages/type.ChannelId.html\" title=\"type sp_messenger::messages::ChannelId\">ChannelId</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the open XDM channel for given chain</p>\n</div></details></div></details>",0,"domain_test_service::domain::EvmDomainNode"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()