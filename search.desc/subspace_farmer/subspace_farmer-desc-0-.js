searchState.loadedDescShard("subspace_farmer", 0, "<code>subspace-farmer</code> library implementation overview\n<code>Identity</code> struct is an abstraction of public &amp; secret key …\nSize of the LRU cache for peers.\n<code>WsClient</code> wrapper.\nCreates new identity, overrides identity that might …\nReturns entropy used to generate keypair.\nSize of the identity file on disk\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a new instance of <code>NodeClient</code>.\nOpens the existing identity, returns <code>Ok(None)</code> if it doesn…\nOpens the existing identity, or creates a new one.\nReturns the public key of the identity.\nReturns the secret key of the identity.\nSign reward hash.\nSubmit a block signature\nSector will expire at the next segment index and should be …\nAuditing\nAuditing details\nDecoded farming error\nSpecial decoded farming error\nSector expiration became known\nDownloaded sector pieces\nDownloading sector pieces\nEncoded sector pieces\nEncoding sector pieces\nPlotting failed\nSector expiration information updated\nSector already expired\nFailed to retrieve farmer info\nFailed to subscribe to slot info notifications\nAbstract farm implementation\nErased error type\nAn identifier for a farm, can be used for in logs, thread …\nErrors that happen during farming\nVarious farming notifications\nFinished plotting\nOpaque handler ID for event handlers, once dropped handler …\nI/O error occurred\nLow-level auditing error\nLow-level proving error\nDefinitely not stored\nNon-fatal farming error\nAbstract piece cache implementation\nOffset wrapper for pieces in <code>PieceCache</code>\nAbstract piece reader implementation\nAbstract plot cache implementation\nGetter for plotted sectors\nSector is being plotted\nProving\nProving details\nResult of the proving\nManaged to prove within time limit, but node rejected …\nDetails about sector expiration\nDetails about sector currently being plotted\nVarious sector updates\nSlot info notification stream ended\nStarting plotting of a sector\nProved successfully and accepted by the node\nProving took too long\nFarm ID\nMaybe has vacant slot to store\nWriting sector\nWritten sector\nMaybe still stored\nContents of this piece cache.\nConsumes <code>HandlerId</code> and prevents handler from being removed …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nID of this farm\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether this error is fatal and makes farm unusable\nCheck if piece is potentially stored in this cache (not …\nMax number of elements in this cache\nCreates new ID\nSubscribe to farming notifications\nSubscribe to sector updates\nSubscribe to new solution notification\nGet piece cache instance\nGet piece reader to read plotted pieces later\nGet plot cache instance\nGet plotted sectors instance\nRead piece from cache at specified offset.\nRead piece from cache.\nRead piece from sector by offset, <code>None</code> means input …\nRead piece index from cache at specified offset.\nWhether proving ended up being successful\nRun and wait for background threads to exit or return an …\nNumber of sectors that were audited\nString variant of the error, primarily for monitoring …\nAudit duration\nAudit duration\nNumber of sectors in this farm\nStore piece in cache if there is free space, otherwise …\nStore piece in cache at specified offset, replacing …\nLower-level error\nLower-level error\nSegment index at which sector expires\nWhether this is the last sector queued so far\nInformation about old plotted sector that was replaced\nInformation about plotted sector\nProgress so far in % (not including this sector)\nWhether sector is being replotted\nHow much time it took to plot a sector\nFarmer cache that aggregates different kinds of caches of …\nFarmer cache worker used to drive the farmer cache backend\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet piece from cache\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nTry to store a piece in additional downloaded pieces, if …\nCreate new piece cache instance and corresponding worker.\nSubscribe to cache sync notifications\nInitialize replacement of backing caches\nRun the cache worker with provided piece getter.\nErased error type\nAbstraction of the Node Client\nNode Client extension methods that are not necessary for …\nAcknowledge segment header.\nGet farmer app info\nGet the last segment headers.\nGet piece by index.\nGet segment headers for the segments\nSubmit a block signature\nSubmit a slot solution\nSubscribe to archived segment headers\nSubscribe to block signing request\nSubscribe to slot\nCan’t preallocate cache file, probably not enough space …\nChecksum mismatch\nI/O error occurred\nOffset outsize of range\nDedicated piece cache stored on one disk, is used both to …\nDisk piece cache open error\nCache size has zero capacity, this is not supported\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nMax offset\nProvided offset\nDownloaded sector pieces\nDownloading sector pieces\nEncoded sector pieces\nEncoding sector pieces\nPlotting failed\nFinished plotting\nAbstract plotter implementation\nSector plotting progress\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nPlot one sector, returns a stream of sector plotting …\nError message\nInformation about plotted sector\nAll plotted sector bytes\nAll plotted sector metadata bytes\nHow much time it took to plot a sector\nCPU plotter\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreate new instance\nSubscribe to plotting progress notifications\nBackground downloading panicked\nErrors that happen in background tasks\nBackground task panicked\nCache can’t be opened\nCache file does not exist\nCan’t preallocate metadata file, probably not enough …\nCan’t preallocate plot file, probably not enough space …\nFailed to open farm\nFailed to create thread pool\nFailed to decode metadata header\nFailed to decode metadata header\nFailed to determine file size\nFailed to retrieve farmer info\nFailed to get segment header\nFailed to open or create identity\nFailed to read bytes from file\nFailed to subscribe to archived segments\nFailed to write bytes from file\nFarm info can’t be opened\nFarm info file does not exist\nFarm is too large\nFarming error\nFarm was found and read successfully\nIdentity can’t be opened\nIdentity file does not exist\nPublic key in identity doesn’t match metadata\nAllocated space is not enough for one sector\nInvalid number pieces in sector\nI/O error occurred\nI/O error occurred\nFarm is likely already in use, make sure no other farmer …\nFarm is likely already in use, make sure no other farmer …\nLow-level plotting error\nMetadata can’t be opened\nMetadata file does not exist\nMetadata file too small\nMissing archived segment header\nFarm was not found\nPiece cache error\nPlotting error\nErrors that happen during plotting\nIdentity public key doesn’t match public key in the disk …\nReward signing\nSingle disk farm abstraction is a container for everything …\nErrors happening when trying to create/open single disk …\nImportant information about the contents of the …\nExclusive lock for single disk farm info file, ensuring no …\nOptions used to open single disk farm\nErrors happening during scrubbing\nSummary of single disk farm for presentational purposes\nFailed to spawn task for blocking thread\nUnexpected metadata version\nUnexpected metadata version\nV0 of the info\nWrong chain (genesis hash)\nHow much space in bytes is allocated for this farm\nHow much space in bytes was allocated\nPercentage of allocated space dedicated for caching …\nCollect summary of single disk farm for presentational …\nPath to directory where farm is stored.\nDisable farm locking, for example if file system doesn’t …\nErasure coding instance to use.\nInformation necessary for farmer application\nThread pool size used for farming (mostly for blocking …\nBarrier before internal benchmarking between different …\nLimit concurrency of internal benchmarking between …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGlobal mutex that can restrict concurrency of …\nID of this farm\nInfo of this farm\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nKzg instance to use.\nLoad <code>SingleDiskFarm</code> from path is supposed to be stored, …\nHow many pieces one sector is supposed to contain (max)\nCreate new single disk farm instance\nRPC client connected to Subspace node\nSubscribe to farming notifications\nSubscribe to sector updates\nSubscribe to new solution notification\nGet piece cache instance\nGet piece reader to read plotted pieces later\nHow many pieces does one sector contain.\nGet plot cache instance\nRead information about sectors plotted so far\nPlotter\nNotification for plotter to start, can be used to delay …\nRead all sectors metadata\nAddress where farming rewards should go\nRun and wait for background threads to exit or return an …\nCheck the farm for corruption and repair errors (caused by …\nStore <code>SingleDiskFarm</code> info to path, so it can be loaded …\nNumber of sectors in this farm\nTry to acquire exclusive lock on the single disk farm info …\nWipe everything that belongs to this single disk farm\nLower-level error\nLower-level error\nLower-level error\nSegment index that was missing\nCurrent allocated space\nHex-encoded genesis hash during farm creation\nPublic key used during farm creation\nFarm ID\nFarm ID\nFarm ID\nNumber of pieces in sector farm is initialized with\nMax supported pieces in sector\nMinimal allocated space\nHex-encoded current genesis hash\nCurrent public key\nHow much space in bytes is allocated for this farm\nGenesis hash of the chain used for farm creation\nID of the farm\nHow many pieces does one sector contain.\nPublic key of identity used for farm creation\nLow-level error\nLow-level error\nLow-level error\nLow-level error\nLow-level error\nLow-level error\nLow-level error\nAffected file\nAffected file\nAffected file\nInfo file\nInfo file\nIdentity file\nIdentity file\nMetadata file\nMetadata file\nMetadata file\nCache file\nCache file\nIdentity public key\nDisk farm info public key\nOffset in the file\nOffset in the file\nReserved size\nNumber of bytes to read\nNumber of bytes to read\nFile size\nPath to directory where farm is stored.\nPath to directory where farm is stored.\nPath to directory where farm is stored.\nError itself\nFarm info\nPlot auditing implementation\nPlot audit options\nErasure coding instance\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nKzg instance\nCreate new instance\nPublic key of the farm\nMode of reading chunks during proving\nReward address to use for solutions\nOptional sector that is currently being modified (for …\nMetadata of all sectors plotted so far\nSlot info for the audit\nProof of space table generator\nWrapper data structure for multiple files to be used with …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nOpen file at specified path as many times as there is …\nOpen file at specified path as many times as there is …\nDedicated piece cache stored on one disk, is used both to …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nWrapper data structure that can be used to read pieces …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nRead piece from sector by offset, <code>None</code> means input …\nChecksum mismatch\nAdditional piece cache that exploit part of the plot that …\nDisk plot cache open error\nI/O error occurred\nFailed to spawn task for blocking thread\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\n4096 is as a relatively safe size due to sector size on …\nWrapper data structure for unbuffered I/O on Windows.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nOpen file at specified path for random unbuffered access …\nTruncates or extends the underlying file, updating the …\nPlotting thread pool manager.\nA wrapper around thread pool pair for plotting purposes\nWrapper around <code>PlottingThreadPoolPair</code> that on <code>Drop</code> will …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet one of inner thread pool pairs, will wait until one is …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate new thread pool manager by instantiating …\nHow many thread pool pairs are being managed here\nJoins async join handle on drop\nAbstraction for CPU core set\nGet all cpu cores, grouped into sets according to NUMA …\nGet cpu core numbers in this set\nCreates thread pool pairs for each of CPU core set pair …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate new instance.\nParse space-separated set of groups of CPU cores …\nPin current thread to this NUMA node (not just one CPU …\nThis function is supposed to be used with …\nRecommended number of thread pool size for farming, equal …\nRegroup CPU core sets to contain at most <code>target_sets</code> sets, …\nRuns future on a dedicated thread with the specified name, …\nModified version of SS58 parser extracted from Substrate …\nThread indices for each thread pool\nThis function is supposed to be used with …\nWill truncate list of CPU cores to this number.\nRetry policy for getting pieces from DSN cache\nWeak farmer piece getter, can be upgraded to …\nExponential backoff between retries\nDowngrade to <code>WeakFarmerPieceGetter</code> in order to break …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nFast way to get piece using various caches\nSlow way to get piece using archival storage\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nMax number of retries when trying to get piece from DSN …\nTry to upgrade to <code>FarmerPieceGetter</code> if there is at least …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nWrapper data structure for pieces plotted under multiple …\nAdd new farm with corresponding piece reader\nAdd new sector to collect plotted pieces\nCheck if piece is known and can be retrieved\nAdd all sectors of the farm\nAdd old sector from plotted pieces (happens on replotting)\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nIterator over all unique piece indices plotted\nRead plotted piece from one of the farms.\nBase 58 requirement is violated\nLength is bad\nDisallowed SS58 Address Format for this datatype\nInvalid checksum\nInvalid SS58 prefix byte\nAn error type for SS58 decoding.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nSome if the string is a properly encoded SS58Check address.")