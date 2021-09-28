import { ApiPromise } from "@polkadot/api";
import { Observable } from "@polkadot/types/types";
import { U64 } from "@polkadot/types/primitive";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { concatMap, take, map } from "rxjs/operators";
import { from, merge } from 'rxjs';
import { Logger } from "pino";
import { ParaHeadAndId, TxData } from "./types";
import { getParaHeadAndIdFromRecord, isRelevantRecord } from './utils'
import Parachain from "./parachain";

type SourceConstructorParams = {
  api: ApiPromise;
  chain: string;
  feedId: U64;
  parachainsMap: Map<string, Parachain>;
  logger: Logger;
  signer: AddressOrPair;
};

type TxDataInput = {
  block: SignedBlock;
  hash: Hash;
  feedId: U64;
  chain: string;
  signer: AddressOrPair;
}

class Source {
  private api: ApiPromise;
  private chain: string;
  private feedId: U64;
  private parachainsMap: Map<string, Parachain>;
  private logger: Logger;
  signer: AddressOrPair;

  constructor(params: SourceConstructorParams) {
    this.api = params.api;
    this.chain = params.chain;
    this.feedId = params.feedId;
    this.parachainsMap = params.parachainsMap;
    this.logger = params.logger;
    this.signer = params.signer;
    this.getBlocksByHeader = this.getBlocksByHeader.bind(this);
    this.getParablocks = this.getParablocks.bind(this);
  }

  private subscribeHeads(): Observable<Header> {
    return this.api.rx.rpc.chain.subscribeFinalizedHeads();
  }

  private getBlock(hash: Hash): Observable<SignedBlock> {
    return this.api.rx.rpc.chain.getBlock(hash).pipe(take(1))
  }

  // TODO: refactor to return Observable<ParaHeadAndId>
  private async getParaHeadsAndIds(block: Block): Promise<ParaHeadAndId[]> {
    const blockRecords = await this.api.query.system.events.at(
      block.header.hash
    );

    const result: ParaHeadAndId[] = [];

    for (let index = 0; index < block.extrinsics.length; index++) {
      const { method } = block.extrinsics[index];

      if (method.section == "paraInherent" && method.method == "enter") {
        blockRecords
          .filter(isRelevantRecord(index))
          .map(getParaHeadAndIdFromRecord)
          .forEach((parablockData) => result.push(parablockData));
      }
    }

    this.logger.info(`Associated parablocks: ${result.length}`);

    return result;
  }

  // TODO: add logging for individual parablocks
  getParablocks({ block }: SignedBlock): Observable<TxData> {
    return from(this.getParaHeadsAndIds(block))
      .pipe(concatMap(x => x))
      .pipe(concatMap(({ paraId, paraHead }) => {
        const parachain = this.parachainsMap.get(paraId);
        if (!parachain) throw new Error(`Uknown paraId: ${paraId}`);

        const { feedId, chain, signer } = parachain;

        return parachain.fetchParaBlock(paraHead)
          .pipe(map((block) => this.addBlockTxData({ block, hash: paraHead, feedId, chain, signer })));
      }));
  }

  private addBlockTxData({ block, hash, feedId, chain, signer }: TxDataInput): TxData {
    const metadata = {
      hash,
      number: block.block.header.number.toString(),
    };

    return {
      feedId,
      block: block.toString(),
      metadata,
      chain,
      signer,
    };
  }

  private getBlocksByHeader({ hash }: Header): Observable<TxData> {
    const relayBlock = this.getBlock(hash);
    const parablocks = relayBlock.pipe(concatMap(this.getParablocks));

    const relayBlockWithMetadata = relayBlock.pipe(
      map(block => this.addBlockTxData({ block, hash, feedId: this.feedId, chain: this.chain, signer: this.signer }))
    );

    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block.toString());
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    this.logger.info(`${this.chain} - finalized block hash: ${hash}`);

    return merge(relayBlockWithMetadata, parablocks);
  }

  subscribeBlocks(): Observable<TxData> {
    return this.subscribeHeads().pipe(concatMap(this.getBlocksByHeader));
  }
}

export default Source;
