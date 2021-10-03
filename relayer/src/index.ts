import { ApiPromise, WsProvider } from "@polkadot/api";
import { merge } from "rxjs";
import { getAccount } from "./account";
import config from "./config";
import Source from "./source";
import Target from "./target";
import logger from "./logger";
import { createParachainsMap, sleep } from './utils';
import { ChainName } from "./types";

const createApi = async (url: string) => {
  const provider = new WsProvider(url);
  const api = await ApiPromise.create({
    provider,
  });

  return api;
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const targetApi = await createApi(config.targetChainUrl);
  const target = new Target({ api: targetApi, logger });

  const sources = await Promise.all(
    config.sourceChainUrls.map(async ({ url, parachains }) => {
      const api = await createApi(url);
      const chain = await api.rpc.system.chain();

      // creating and delegating to new accounts
      const master = getAccount(config.accountSeed);
      const sourceSigner = getAccount(`${config.accountSeed}/${chain}`);
      const paraSigners = parachains.map(({ paraId }) => getAccount(`${config.accountSeed}/${paraId}`));
      // TODO: master has to delegate spending to sourceSigner and paraSigners
      for (const delegate of [sourceSigner, ...paraSigners]) {
        // send 1.5 units
        // TODO: investigate why 0.5 existential deposit is not enough - probably some fees are involved
        await target.sendBalanceTx(master, delegate, 1.5);
        // add this account as proxy for master
        // await target.sendAddProxyTx(master, delegate);
      }

      // TODO: clean later
      await sleep(15000);

      const feedId = await target.sendCreateFeedTx(sourceSigner);
      const parachainsMap = await createParachainsMap(target, parachains, paraSigners);

      return new Source({
        api,
        chain: chain.toString() as ChainName,
        parachainsMap,
        logger,
        feedId,
        signer: sourceSigner,
      });
    })
  );

  const blockSubscriptions = merge(...sources.map((source) => source.subscribeBlocks()));

  target.processSubscriptions(blockSubscriptions).subscribe();
})();
