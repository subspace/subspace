(function() {var type_impls = {
"auto_id_domain_runtime":[],
"domain_runtime_primitives":[],
"evm_domain_runtime":[],
"evm_domain_test_runtime":[],
"sp_domains":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CDomainId%3E-for-u32\" class=\"impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#155-160\">source</a><a href=\"#impl-From%3CDomainId%3E-for-u32\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a>&gt; for <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/sp_domains/lib.rs.html#157-159\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(domain_id: <a class=\"struct\" href=\"sp_domains/struct.DomainId.html\" title=\"struct sp_domains::DomainId\">DomainId</a>) -&gt; Self</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<DomainId>","sp_domains::RuntimeId","sp_domains::EpochIndex"]],
"subspace_core_primitives":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CPieceOffset%3E-for-u32\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_core_primitives/pieces.rs.html#278-283\">source</a><a href=\"#impl-From%3CPieceOffset%3E-for-u32\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"subspace_core_primitives/struct.PieceOffset.html\" title=\"struct subspace_core_primitives::PieceOffset\">PieceOffset</a>&gt; for <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_core_primitives/pieces.rs.html#280-282\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(original: <a class=\"struct\" href=\"subspace_core_primitives/struct.PieceOffset.html\" title=\"struct subspace_core_primitives::PieceOffset\">PieceOffset</a>) -&gt; Self</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<PieceOffset>","subspace_core_primitives::BlockNumber"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CSBucket%3E-for-u32\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_core_primitives/pieces.rs.html#103-108\">source</a><a href=\"#impl-From%3CSBucket%3E-for-u32\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"subspace_core_primitives/struct.SBucket.html\" title=\"struct subspace_core_primitives::SBucket\">SBucket</a>&gt; for <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_core_primitives/pieces.rs.html#105-107\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(original: <a class=\"struct\" href=\"subspace_core_primitives/struct.SBucket.html\" title=\"struct subspace_core_primitives::SBucket\">SBucket</a>) -&gt; Self</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<SBucket>","subspace_core_primitives::BlockNumber"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3CU256%3E-for-u32\" class=\"impl\"><a class=\"src rightside\" href=\"src/subspace_core_primitives/lib.rs.html#941-948\">source</a><a href=\"#impl-TryFrom%3CU256%3E-for-u32\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"subspace_core_primitives/struct.U256.html\" title=\"struct subspace_core_primitives::U256\">U256</a>&gt; for <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.str.html\">str</a></h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/subspace_core_primitives/lib.rs.html#945-947\">source</a><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(value: <a class=\"struct\" href=\"subspace_core_primitives/struct.U256.html\" title=\"struct subspace_core_primitives::U256\">U256</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, Self::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#associatedtype.Error\" title=\"type core::convert::TryFrom::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Performs the conversion.</div></details></div></details>","TryFrom<U256>","subspace_core_primitives::BlockNumber"]],
"subspace_runtime_primitives":[]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()