import logo from './logo.svg';
import './App.css';
import { useEffect } from 'react';
import FireEvmKeyringsController, { testKring } from './libs/FireEvmKeyringsController';
const {log, cloneDeep, untilFinalized} = require('./utils/common.js');
const PolkaKeyring = require('@polkadot/keyring');
const PolkaAPIs = require('@polkadot/api');
const PolkaRPCs = require('@polkadot/rpc-provider');
const MMaskHdKeyring = require('@metamask/eth-hd-keyring');
const PolkaUtilCrypto = require('@polkadot/util-crypto');
const MMaskEthSigUtils = require('@metamask/eth-sig-util');
const XtensionDapp = require('@polkadot/extension-dapp');

window.deps = {};

async function run1() {
  const addr = 'http://localhost:9933';
  const ws = new window.deps.pRpc.HttpProvider(addr);
  const api = await window.deps.pApi.ApiPromise.create({provider: ws, noInitWarn: !0});
  const amount = 1000000000000000000n;
  const tx = api.tx.balances.transferKeepAlive('5CriHXW2BsX1kzGiWqvKxQBhBLxm3BRFiCswR6qqcF6H9JkX', amount);
  const al = new window.deps.pKring.Keyring();
  al.addFromUri('//Alice', {}, 'sr25519');
  const signer = al.pairs[0];
  const bal = await api.query.balances.account(signer.address);
  log.i('alice bal:', bal.toHuman());
  // if(bal.free > amount) {
  const r = await untilFinalized({tx, signer});
  log.i('result:', r);
  // }
}

async function runall() {
  await run1();
}

function App() {
  useEffect(async _ => {
    window.deps['runall'] = runall;
    window.deps['pRpc'] = PolkaRPCs;
    window.deps['pApi'] = PolkaAPIs;
    window.deps['kTest'] = testKring;
    window.deps['xdap'] = XtensionDapp;
    window.deps['pKring'] = PolkaKeyring;
    window.deps['mKring'] = MMaskHdKeyring;
    window.deps['pUtilCrypt'] = PolkaUtilCrypto;
    window.deps['mMEthSigUtil'] = MMaskEthSigUtils;
    window.deps['hybKring'] = FireEvmKeyringsController;
  }, [])

  return (
    <div className="App">
      <header className="App-header">
        <p>Welcome, please open console and check <b>window.deps</b></p>
      </header>
    </div>
  );
}

export default App;
