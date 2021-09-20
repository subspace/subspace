import { ApiPromise } from "@polkadot/api";
import { merge } from "rxjs";
import { concatMap } from "rxjs/operators";
import { Logger } from "pino";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { Hash } from "@polkadot/types/interfaces";
import { Observable } from "@polkadot/types/types";

import { TxData } from "./types";

type TargetConstructorParams = {
  api: ApiPromise;
  signer: AddressOrPair;
  logger: Logger;
};

class Target {
  private api: ApiPromise;
  private signer: AddressOrPair;
  private logger: Logger;

  constructor({ api, signer, logger }: TargetConstructorParams) {
    this.api = api;
    this.signer = signer;
    this.logger = logger;
    this.processBlocks = this.processBlocks.bind(this);
    this.sendBlockTx = this.sendBlockTx.bind(this);
  }

  private sendBlockTx({ block, chainId }: TxData): Promise<Hash> {
    return (
      this.api.tx.feeds
        .put(block, chainId)
        // it is required to specify nonce, otherwise transaction within same block will be rejected
        // if nonce is -1 API will do the lookup for the right value
        // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
        .signAndSend(this.signer, { nonce: -1 })
    );
  }

  private async processBlocks(blocks: TxData[]) {
    for await (const block of blocks) {
      const txHash = await this.sendBlockTx(block);
      this.logger.info(`Transaction sent: ${txHash}`);
    }
  }

  processSubscriptions(
    subscriptions: Observable<TxData[]>[]
  ): Observable<void> {
    return merge(...subscriptions).pipe(
      // subscriptions emit array of blocks - relay block and parablocks
      concatMap(this.processBlocks)
    );
  }
}

export default Target;
