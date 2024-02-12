(function() {var type_impls = {
"pallet_rewards":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-GetStorageVersion-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#impl-GetStorageVersion-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; GetStorageVersion for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.CurrentStorageVersion\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.CurrentStorageVersion\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">CurrentStorageVersion</a> = NoStorageVersionSet</h4></section></summary><div class='docblock'>This will be filled out by the <a href=\"crate::pallet\"><code>pallet</code></a> macro. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.current_storage_version\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.current_storage_version\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">current_storage_version</a>() -&gt; Self::CurrentStorageVersion</h4></section></summary><div class='docblock'>Returns the current storage version as supported by the pallet.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_chain_storage_version\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.on_chain_storage_version\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_chain_storage_version</a>() -&gt; StorageVersion</h4></section></summary><div class='docblock'>Returns the on-chain storage version of the pallet as stored in the storage.</div></details></div></details>","GetStorageVersion","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hooks%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#99-108\">source</a><a href=\"#impl-Hooks%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; Hooks&lt;&lt;&lt;&lt;T as Config&gt;::Block as HeaderProvider&gt;::HeaderT as Header&gt;::Number&gt; for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_initialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#100-103\">source</a><a href=\"#method.on_initialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_initialize</a>(block_number: BlockNumberFor&lt;T&gt;) -&gt; Weight</h4></section></summary><div class='docblock'>Block initialization hook. This is called at the very beginning of block execution. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_finalize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#105-107\">source</a><a href=\"#method.on_finalize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_finalize</a>(now: BlockNumberFor&lt;T&gt;)</h4></section></summary><div class='docblock'>Block finalization hook. This is called at the very end of block execution. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_idle\" class=\"method trait-impl\"><a href=\"#method.on_idle\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_idle</a>(_n: BlockNumber, _remaining_weight: Weight) -&gt; Weight</h4></section></summary><div class='docblock'>Hook to consume a block’s idle time. This will run when the block is being finalized (before\n[<code>Hooks::on_finalize</code>]). <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_runtime_upgrade\" class=\"method trait-impl\"><a href=\"#method.on_runtime_upgrade\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_runtime_upgrade</a>() -&gt; Weight</h4></section></summary><div class='docblock'>Hook executed when a code change (aka. a “runtime upgrade”) is detected by FRAME. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.offchain_worker\" class=\"method trait-impl\"><a href=\"#method.offchain_worker\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">offchain_worker</a>(_n: BlockNumber)</h4></section></summary><div class='docblock'>Implementing this function on a pallet allows you to perform long-running tasks that are\ndispatched as separate threads, and entirely independent of the main wasm runtime. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.integrity_test\" class=\"method trait-impl\"><a href=\"#method.integrity_test\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">integrity_test</a>()</h4></section></summary><div class='docblock'>Check the integrity of this pallet’s configuration. <a>Read more</a></div></details></div></details>","Hooks<<<<T as Config>::Block as HeaderProvider>::HeaderT as Header>::Number>","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#impl-Clone-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; Self</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#impl-PartialEq-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OnRuntimeUpgrade-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-OnRuntimeUpgrade-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; OnRuntimeUpgrade for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_runtime_upgrade\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.on_runtime_upgrade\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_runtime_upgrade</a>() -&gt; Weight</h4></section></summary><div class='docblock'>See [<code>Hooks::on_runtime_upgrade</code>].</div></details></div></details>","OnRuntimeUpgrade","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#impl-Debug-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, fmt: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Callable%3CT%3E-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#44-109\">source</a><a href=\"#impl-Callable%3CT%3E-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; Callable&lt;T&gt; for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"associatedtype.RuntimeCall\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.RuntimeCall\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">RuntimeCall</a> = <a class=\"enum\" href=\"pallet_rewards/enum.Call.html\" title=\"enum pallet_rewards::Call\">Call</a>&lt;T&gt;</h4></section></div></details>","Callable<T>","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-StorageInfoTrait-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#impl-StorageInfoTrait-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; StorageInfoTrait for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.storage_info\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.storage_info\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">storage_info</a>() -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;StorageInfo&gt;</h4></section></div></details>","StorageInfoTrait","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OnFinalize%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-OnFinalize%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; OnFinalize&lt;&lt;&lt;&lt;T as Config&gt;::Block as HeaderProvider&gt;::HeaderT as Header&gt;::Number&gt; for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_finalize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.on_finalize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_finalize</a>(n: BlockNumberFor&lt;T&gt;)</h4></section></summary><div class='docblock'>See [<code>Hooks::on_finalize</code>].</div></details></div></details>","OnFinalize<<<<T as Config>::Block as HeaderProvider>::HeaderT as Header>::Number>","pallet_rewards::pallet::Module"],["<section id=\"impl-Eq-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#56\">source</a><a href=\"#impl-Eq-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section>","Eq","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PalletInfoAccess-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#impl-PalletInfoAccess-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; PalletInfoAccess for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.index\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.index\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">index</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>Index of the pallet as configured in the runtime.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.name\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.name\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">name</a>() -&gt; &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.str.html\">str</a></h4></section></summary><div class='docblock'>Name of the pallet as configured in the runtime.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.name_hash\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.name_hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">name_hash</a>() -&gt; [<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">16</a>]</h4></section></summary><div class='docblock'>Two128 hash of name.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.module_name\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.module_name\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">module_name</a>() -&gt; &amp;'static <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.str.html\">str</a></h4></section></summary><div class='docblock'>Name of the Rust module containing the pallet.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.crate_version\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.crate_version\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">crate_version</a>() -&gt; CrateVersion</h4></section></summary><div class='docblock'>Version of the crate containing the pallet.</div></details></div></details>","PalletInfoAccess","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PalletsInfoAccess-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#impl-PalletsInfoAccess-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; PalletsInfoAccess for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.count\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.count\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">count</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>The number of pallets’ information that this type represents. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.infos\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.infos\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">infos</a>() -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;PalletInfoData&gt;</h4></section></summary><div class='docblock'>All of the pallets’ information that this type represents.</div></details></div></details>","PalletsInfoAccess","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OnInitialize%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-OnInitialize%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; OnInitialize&lt;&lt;&lt;&lt;T as Config&gt;::Block as HeaderProvider&gt;::HeaderT as Header&gt;::Number&gt; for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_initialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.on_initialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_initialize</a>(n: BlockNumberFor&lt;T&gt;) -&gt; Weight</h4></section></summary><div class='docblock'>See [<code>Hooks::on_initialize</code>].</div></details></div></details>","OnInitialize<<<<T as Config>::Block as HeaderProvider>::HeaderT as Header>::Number>","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OnGenesis-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#impl-OnGenesis-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; OnGenesis for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_genesis\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#55\">source</a><a href=\"#method.on_genesis\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_genesis</a>()</h4></section></summary><div class='docblock'>Something that should happen at genesis.</div></details></div></details>","OnGenesis","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-IntegrityTest-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-IntegrityTest-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; IntegrityTest for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.integrity_test\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.integrity_test\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">integrity_test</a>()</h4></section></summary><div class='docblock'>See [<code>Hooks::integrity_test</code>].</div></details></div></details>","IntegrityTest","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OnIdle%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-OnIdle%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; OnIdle&lt;&lt;&lt;&lt;T as Config&gt;::Block as HeaderProvider&gt;::HeaderT as Header&gt;::Number&gt; for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.on_idle\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.on_idle\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">on_idle</a>(n: BlockNumberFor&lt;T&gt;, remaining_weight: Weight) -&gt; Weight</h4></section></summary><div class='docblock'>See [<code>Hooks::on_idle</code>].</div></details></div></details>","OnIdle<<<<T as Config>::Block as HeaderProvider>::HeaderT as Header>::Number>","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OffchainWorker%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-OffchainWorker%3C%3C%3C%3CT+as+Config%3E::Block+as+HeaderProvider%3E::HeaderT+as+Header%3E::Number%3E-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; OffchainWorker&lt;&lt;&lt;&lt;T as Config&gt;::Block as HeaderProvider&gt;::HeaderT as Header&gt;::Number&gt; for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.offchain_worker\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.offchain_worker\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">offchain_worker</a>(n: BlockNumberFor&lt;T&gt;)</h4></section></summary><div class='docblock'>This function is being called after every block import (when fully synced). <a>Read more</a></div></details></div></details>","OffchainWorker<<<<T as Config>::Block as HeaderProvider>::HeaderT as Header>::Number>","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-WhitelistedStorageKeys-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#impl-WhitelistedStorageKeys-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; WhitelistedStorageKeys for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.whitelisted_storage_keys\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#43\">source</a><a href=\"#method.whitelisted_storage_keys\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">whitelisted_storage_keys</a>() -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;TrackedStorageKey&gt;</h4></section></summary><div class='docblock'>Returns a <a href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\"><code>Vec&lt;TrackedStorageKey&gt;</code></a> indicating the storage keys that\nshould be whitelisted during benchmarking. This means that those keys\nwill be excluded from the benchmarking performance calculation.</div></details></div></details>","WhitelistedStorageKeys","pallet_rewards::pallet::Module"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-BeforeAllRuntimeMigrations-for-Pallet%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#impl-BeforeAllRuntimeMigrations-for-Pallet%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"pallet_rewards/trait.Config.html\" title=\"trait pallet_rewards::Config\">Config</a>&gt; BeforeAllRuntimeMigrations for <a class=\"struct\" href=\"pallet_rewards/struct.Pallet.html\" title=\"struct pallet_rewards::Pallet\">Pallet</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.before_all_runtime_migrations\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/pallet_rewards/lib.rs.html#98\">source</a><a href=\"#method.before_all_runtime_migrations\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">before_all_runtime_migrations</a>() -&gt; Weight</h4></section></summary><div class='docblock'>Something that should happen before runtime migrations are executed.</div></details></div></details>","BeforeAllRuntimeMigrations","pallet_rewards::pallet::Module"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()