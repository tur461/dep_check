import logo from './logo.svg';
import './App.css';
import { useEffect } from 'react';
const Utils = require('./common');
const PolkaKeyring = require('@polkadot/keyring');
const MMaskHdKeyring = require('@metamask/eth-hd-keyring');
const PolkaUtilCrypto = require('@polkadot/util-crypto');
const MMaskEthSigUtils = require('@metamask/eth-sig-util');

window.deps = {};

function App() {
  useEffect(_ => {
    window.deps['util'] = Utils;
    window.deps['pKring'] = PolkaKeyring;
    window.deps['mKring'] = MMaskHdKeyring;
    window.deps['pUtilCrypt'] = PolkaUtilCrypto;
    window.deps['mMEthSigUtil'] = MMaskEthSigUtils;
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
