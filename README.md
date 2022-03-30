<h1 align="center">
  <a href="https://github.com/subspace/subspace">
    <img src="https://assets.website-files.com/61526a2af87a54e565b0ae92/6155fc8597a1468aa6dfba07_Group%20201.svg" alt="Logo">
  </a>
</h1>
<div align="center">
  <h2>Subspace Network Monorepo</h2>
  <br />

[![Latest Release](https://img.shields.io/github/v/release/subspace/subspace?display_name=tag&style=flat-square)](https://github.com/subspace/subspace/releases) [![Downloads Latest](https://img.shields.io/github/downloads/subspace/subspace/latest/total?style=flat-square)](https://github.com/subspace/subspace/releases/latest) 

 [![Rust Docs](https://img.shields.io/docsrs/subspace?style=flat-square)](https://subspace.github.io/subspace/)  [![Rust](https://img.shields.io/github/workflow/status/subspace/subspace/Rust?style=flat-square)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

</div>

---

## Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
  - `subspace-node` is an implementation of the node for Subspace protocol
  - `subspace-farmer` is a CLI farmer app
- `cumulus` contains modified copies of Cumulus crates that we use right now
- `polkadot` contains modified copies of Polkadot crates that we use right now
- `substrate` contains modified copies of Substrate's crates that we use for testing

## How to run

Please refer to [farming.md](/docs/farming.md) on how to run farmer. 

If you are looking to farm offline, or build from source for developemental purposes please refer to [development.md](/docs/development.md).
