(function() {var implementors = {
"domain_pallet_executive":[["impl&lt;ExecutiveConfig: <a class=\"trait\" href=\"domain_pallet_executive/trait.Config.html\" title=\"trait domain_pallet_executive::Config\">Config</a> + Config + EnsureInherentsAreFirst&lt;&lt;ExecutiveConfig as Config&gt;::Block&gt;, Context: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>, UnsignedValidator, AllPalletsWithSystem: OnRuntimeUpgrade + BeforeAllRuntimeMigrations + OnInitialize&lt;BlockNumberFor&lt;ExecutiveConfig&gt;&gt; + OnIdle&lt;BlockNumberFor&lt;ExecutiveConfig&gt;&gt; + OnFinalize&lt;BlockNumberFor&lt;ExecutiveConfig&gt;&gt; + OffchainWorker&lt;BlockNumberFor&lt;ExecutiveConfig&gt;&gt; + OnPoll&lt;BlockNumberFor&lt;ExecutiveConfig&gt;&gt;, COnRuntimeUpgrade: OnRuntimeUpgrade&gt; ExecuteBlock&lt;&lt;ExecutiveConfig as Config&gt;::Block&gt; for <a class=\"struct\" href=\"domain_pallet_executive/struct.Executive.html\" title=\"struct domain_pallet_executive::Executive\">Executive</a>&lt;ExecutiveConfig, Context, UnsignedValidator, AllPalletsWithSystem, COnRuntimeUpgrade&gt;<div class=\"where\">where\n    &lt;&lt;ExecutiveConfig as Config&gt;::Block as BlockT&gt;::Extrinsic: Checkable&lt;Context&gt; + Codec,\n    <a class=\"type\" href=\"domain_pallet_executive/type.CheckedOf.html\" title=\"type domain_pallet_executive::CheckedOf\">CheckedOf</a>&lt;&lt;&lt;ExecutiveConfig as Config&gt;::Block as BlockT&gt;::Extrinsic, Context&gt;: Applyable + GetDispatchInfo,\n    <a class=\"type\" href=\"domain_pallet_executive/type.CallOf.html\" title=\"type domain_pallet_executive::CallOf\">CallOf</a>&lt;&lt;&lt;ExecutiveConfig as Config&gt;::Block as BlockT&gt;::Extrinsic, Context&gt;: Dispatchable&lt;Info = DispatchInfo, PostInfo = PostDispatchInfo&gt;,\n    <a class=\"type\" href=\"domain_pallet_executive/type.OriginOf.html\" title=\"type domain_pallet_executive::OriginOf\">OriginOf</a>&lt;&lt;&lt;ExecutiveConfig as Config&gt;::Block as BlockT&gt;::Extrinsic, Context&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;&lt;ExecutiveConfig as Config&gt;::AccountId&gt;&gt;,\n    UnsignedValidator: ValidateUnsigned&lt;Call = <a class=\"type\" href=\"domain_pallet_executive/type.CallOf.html\" title=\"type domain_pallet_executive::CallOf\">CallOf</a>&lt;&lt;&lt;ExecutiveConfig as Config&gt;::Block as BlockT&gt;::Extrinsic, Context&gt;&gt;,</div>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()