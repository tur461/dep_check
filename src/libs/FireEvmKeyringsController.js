const { EventEmitter } = require('events');
const ObservableStore = require('obs-store');
const pHdKeyring = require('@polkadot/keyring');
const { EVENT } = require('../Constants/events');
const pUtilCrypto = require('@polkadot/util-crypto');
const mHdKeyring = require('@metamask/eth-hd-keyring');
const mEncryptor = require('@metamask/browser-passworder');
const { KEYRINGS_TYPE, ERR_STR } = require('../Constants/hdwallet');
const { rEq, isStr, noHexPrefix, log, isEmpty } = require('../utils/common');

const defaultKringBuilders = [
    kringBuilder(mHdKeyring, KEYRINGS_TYPE.EVM),
    kringBuilder(pHdKeyring.Keyring, KEYRINGS_TYPE.FIRE),
];

// log.i('default:', defaultKringBuilders);

const normalizeAddress = a => a.indexOf('0x') != -1 ? a : `0x${a}`;

export default class FireEvmKeyringsController extends EventEmitter {
    constructor(opts) {
        super();
        const initState = opts.initState || {};
        this.kringBuilders = opts.kringBuilders
            ? defaultKringBuilders.concat(opts.kringBuilders)
            : defaultKringBuilders;
            this.store = new ObservableStore(initState);
        this.memStore = new ObservableStore({
            isUnlocked: false,
            keyringTypes: this.kringBuilders.map(builder => builder.type),
            hdPath: 0,
            keyrings: [],
            encryptionKey: opts.encryptionKey || null,
        });

        this.encryptor = opts.encryptor || mEncryptor;
        this.password = opts.password || null;
        this.krings = [];
        this._unsupportedKeyrings = [];

    }
    // creates new wallet with one account
    /**
   * Create New Vault And Keychain
   * Destroys any old encrypted storage,
   * creates a new encrypted store with the given password,
   * randomly creates a new HD wallet with 1 account,
   * faucets that account on the testnet.
   * @fires KeyringController#unlock
   * @param {string} password - The password to encrypt the vault with.
   * @returns {Promise<object>} A Promise that resolves to the state.
   */
    async createNewVaultAndKeychain(password) {
        this.password = password;
        await this.createFirstKeyTree();
        this.setUnlocked();
        return this.fullUpdate();
    }

    /**
     * Create First Key Tree.
     *
     * - Clears the existing vault.
     * - Creates a new vault.
     * - Creates a random new HD Keyring with 1 account.
     * - Makes that account the selected account.
     * - Faucets that account on testnet.
     * - Puts the current seed words into the state tree.
     *
     * @returns {Promise<void>} A promise that resolves if the operation was successful.
     */
    async createFirstKeyTree() {
        this.clearKrings();

        await this.addNewKrings();
        const [evmFirstAcc] = await this.getAccounts(KEYRINGS_TYPE.EVM);
        const [fireFirstAcc] = await this.getAccounts(KEYRINGS_TYPE.FIRE);
        
        if (!evmFirstAcc) throw new Error(ERR_STR.NO_EVM_ACC);
        if (!fireFirstAcc) throw new Error(ERR_STR.NO_FIRE_ACC);

        const hexAccount = normalizeAddress(evmFirstAcc);
        this.emit(
            EVENT.NEW_VAULT, { 
                evmAccount: hexAccount, 
                fireAccount: fireFirstAcc 
        });
        return null;
    }

    /**
     * CreateNewVaultAndRestore
     * Destroys any old encrypted storage,
     * creates a new encrypted store with the given password,
     * creates a new HD wallet from the given seed with 1 account.
     * @fires KeyringController#unlock
     * @param {string} password - The password to encrypt the vault with.
     * @param {Uint8Array | string} seedPhrase - The BIP39-compliant seed phrase,
     * either as a string or Uint8Array.
     * @returns {Promise<object>} A Promise that resolves to the state.
     */
    async createNewVaultAndRestore(password, mnemonic) {
        if (!isStr(password)) throw new Error(ERR_STR.PWD_NOT_TEXT);
        this.password = password;

        await this.clearKrings();
        await this.addNewKrings({ password, mnemonic });

        const [evmFirstAcc] = await this.getAccounts(KEYRINGS_TYPE.EVM);
        const [fireFirstAcc] = await this.getAccounts(KEYRINGS_TYPE.FIRE);
        
        if (!evmFirstAcc) throw new Error(ERR_STR.NO_EVM_ACC);
        if (!fireFirstAcc) throw new Error(ERR_STR.NO_FIRE_ACC);

        this.setUnlocked();
        return this.fullUpdate();
    }

    async signTransaction(ethTx, _fromAddress, ctype, opts = {}) {
        const fromAddress = normalizeAddress(_fromAddress);
        const keyring = await this.getKeyringForAccount(fromAddress);
        return await keyring.signTransaction(fromAddress, ethTx, opts);
    }

    async signMessage(msgParams, ctype, opts = {}) {
        const address = normalizeAddress(msgParams.from);
        const keyring = await this.getKeyringForAccount(address);
        return await keyring.signMessage(address, msgParams.data, opts);
    }

    async addNewKrings(opts = {}) {
        let evmKring = null, fireKring = null; 
        if(opts.password && opts.mnemonic) {
            evmKring = await this._getNewKringWithData(KEYRINGS_TYPE.EVM, {
                hdPath: "",
                mnemonic: opts.mnemonic,
                password: opts.password,
            });
            fireKring = await this._getNewKringWithData(KEYRINGS_TYPE.FIRE, {
                hdPath: 0,
                mnemonic: opts.mnemonic,
                password: opts.password,
            });
            log.i('[addNewKrings]', opts.mnemonic);
        } else {
            evmKring = await this._newKring(KEYRINGS_TYPE.EVM);
            fireKring = await this._newKring(KEYRINGS_TYPE.FIRE);
            const mnemonic = pUtilCrypto.mnemonicGenerate().trim();
            log.i('[addNewKrings]', mnemonic);
            evmKring._initFromMnemonic(mnemonic);
            const hdPath = 0;
            fireKring.addFromUri(`${mnemonic}//${hdPath}`, {})
            log.i('[addNewKrings]', `${mnemonic}//${hdPath}`);
            this.memStore.updateState({hdPath: hdPath + 1});
        }
        await evmKring.addAccounts();
        
        this.krings.push(evmKring);
        this.krings.push(fireKring);

        // const evmAccs = await this.getAccounts(KEYRINGS_TYPE.EVM);
        // const fireAccs = await this.getAccounts(KEYRINGS_TYPE.FIRE);
        
        // await this.checkForDuplicate(KEYRINGS_TYPE.EVM, evmAccs);
        // await this.checkForDuplicate(KEYRINGS_TYPE.FIRE, fireAccs);
        await this.persistAllKrings();
        
        this.fullUpdate();
    
        return this.krings;
    }

    // done
    async _newKring(type) {
        const kringBuilder = this.getKringBuilderForType(type);
        log.i('builder', kringBuilder);
        if (!kringBuilder) return undefined;
        const keyring = kringBuilder();
        log.i('keyring success', type);
        return keyring;
    }
    // done
    async _getNewKringWithData(type, data) {
        const keyringBuilder = this.getKringBuilderForType(type);
    
        if (!keyringBuilder) return undefined;
    
        const keyring = keyringBuilder();
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            await keyring.deserialize(data);
            if (keyring.init) await keyring.init();
        } else {
            const hdPath = +data.hdPath;
            const mnemonic = isStr(data.mnemonic) ? 
                data.mnemonic : 
                String.fromCharCode(...data.mnemonic).trim();
            log.i('[_getNewKringWithData]', `${mnemonic}//${hdPath}`);
            await keyring.addFromUri(`${mnemonic}//${hdPath}`, {});
        }
    
    
        return keyring;
    }

    /**
     * Unlock Keyrings.
     *
     * Attempts to unlock the persisted encrypted storage,
     * initializing the persisted keyrings to RAM.
     *
     * @param {string} password - The keyring controller password.
     * @param {string} encryptionKey - An exported key string to unlock keyrings with.
     * @param {string} encryptionSalt - The salt used to encrypt the vault.
     * @returns {Promise<Array<Keyring>>} The keyrings.
     */
    async unlockKrings(password, encryptionKey, encryptionSalt) {
        const encryptedVault = this.store.getState().vault;
        if (!encryptedVault) throw new Error(ERR_STR.NO_PREV_ENC_VAULT);

        await this.clearKrings();

        let vault;

        if (this.cacheEncryptionKey) {
            if (password) {
                const result = await this.encryptor.decryptWithDetail(
                    password,
                    encryptedVault,
                );
                vault = result.vault;
                this.password = password;

                this.memStore.updateState({
                    encryptionKey: result.exportedKeyString,
                    encryptionSalt: result.salt,
                });
            } else {
                const parsedEncryptedVault = JSON.parse(encryptedVault);

                if (encryptionSalt !== parsedEncryptedVault.salt) throw new Error(ERR_STR.KEY_AND_SALT_XPIRED);

                const key = await this.encryptor.importKey(encryptionKey);
                vault = await this.encryptor.decryptWithKey(key, parsedEncryptedVault);

                // This call is required on the first call because encryptionKey
                // is not yet inside the memStore
                this.memStore.updateState({
                    encryptionKey,
                    encryptionSalt,
                });
            }
        } else {
            vault = await this.encryptor.decrypt(password, encryptedVault);
            this.password = password;
        }

        await Promise.all(vault.map(this._restoreKring.bind(this)));
        await this._updateMemStoreKeyrings();
        return this.krings;
    }

    /**
     * Restore Keyring Helper
     * Attempts to initialize a new keyring from the provided serialized payload.
     * On success, returns the resulting keyring instance.
     * @param {object} serialized - The serialized keyring.
     * @returns {Promise<Keyring|undefined>} The deserialized keyring or undefined if the keyring type is unsupported.
     */
    async _restoreKring(serialized) {
        const { type, data } = serialized;
        // log.i('[_restoreKring]', data, type);
        const keyring = await this._getNewKringWithData(type, data);
        if (!keyring) {
            this._unsupportedKeyrings.push(serialized);
            return undefined;
        }

        // getAccounts also validates the accounts for some keyrings
        if(rEq(type, KEYRINGS_TYPE.EVM)) await keyring.getAccounts();
        this.krings.push(keyring);
        return keyring;
    }

    async addNewAccounts(kring) {
        if(rEq(kring.type, KEYRINGS_TYPE.EVM)) {
                await this.krings[0].addAccounts();
        } else {
            
        }
        this.emit(EVENT.KRING.ACCS_ADDED);
    }

    // done
    // check for dupl by checking just first elem
    async checkForDuplicate(type, newAccArr) {
        const accs = await this.getAccounts(type);
        log.i('[checkForDuplicate] accs:', newAccArr, accs);
        let isIncl = !1;
        switch (type) {
            case KEYRINGS_TYPE.EVM:
                isIncl = Boolean(
                    accs.find(acc =>
                        rEq(acc, newAccArr[0]) ||
                        rEq(acc, noHexPrefix(newAccArr[0])),
                    ),
                );

                if (isIncl) {
                throw new Error(
                    'The account you are trying to import is a duplicate',
                );
                }
                return newAccArr;
            case KEYRINGS_TYPE.FIRE:
                isIncl = Boolean(accs.find(acc => rEq(acc, newAccArr[0])));
                if (isIncl)
                    throw new Error(
                        'The account you are trying to import is a duplicate',
                    );
                return newAccArr;
            default: break;
        }
    }
    // done
    async getAccounts(type) {
        if(isEmpty(this.krings)) return [];
        if(rEq(type, KEYRINGS_TYPE.EVM))
            return await this.getEvmAccounts();
        return this.getFireAccounts();
    }
    // done
    async getEvmAccounts() {
        const kring = this.getKringByType(KEYRINGS_TYPE.EVM);
        // log.i('[getEvmAccounts] kring:', kring);
        const accs = await kring.getAccounts();
        const addrs = accs.reduce((res, arr) => res.concat(arr), []);
        return addrs.map(normalizeAddress);
    }
    // done
    getFireAccounts() {
        const kring = this.getKringByType(KEYRINGS_TYPE.FIRE);
        return kring.getPairs().map(p => p.address);
    }

    /**
     * done
     * Persist All Keyrings
     *
     * Iterates the current `keyrings` array,
     * serializes each one into a serialized array,
     * encrypts that array with the provided `password`,
     * and persists that encrypted string to storage.
     *
     * @returns {Promise<boolean>} Resolves to true once keyrings are persisted.
     */
    async persistAllKrings() {
        const { 
            encryptionKey, 
            encryptionSalt 
        } = this.memStore.getState();
        log.i('[persistAllKrings]', this.password);
        if (!this.password && !encryptionKey)
            throw new Error(ERR_STR.PERSIST);
        const evmSer = await this.krings[0].serialize();
        
        const serializedKeyrings = [
            {
                type: this.krings[0].type,
                data: evmSer,
            },
            {
                type: this.krings[1].type,
                data: {
                    hdPath: this.memStore.getState().hdPath,
                    mnemonic: evmSer.mnemonic,
                    numberOfAccounts: this.krings[1].pairs.length,
                }
            }
        ]
        // log.i('[persistAllKrings] serializedKeyrings:', serializedKeyrings);
        let vault;
        let newEncryptionKey;

        if (this.cacheEncryptionKey) {
        if (this.password) {
            const { vault: newVault, exportedKeyString } =
            await this.encryptor.encryptWithDetail(
                this.password,
                serializedKeyrings,
            );

            vault = newVault;
            newEncryptionKey = exportedKeyString;
        } else if (encryptionKey) {
            const key = await this.encryptor.importKey(encryptionKey);
            const vaultJSON = await this.encryptor.encryptWithKey(
            key,
            serializedKeyrings,
            );
            vaultJSON.salt = encryptionSalt;
            vault = JSON.stringify(vaultJSON);
        }
        } else {
            // log.i('[persistAllKrings]', this.password, serializedKeyrings);
            vault = await this.encryptor.encrypt(this.password, serializedKeyrings);
        }

        if (!vault) throw new Error(ERR_STR.NO_VAULT_INFO);

        this.store.updateState({ vault });

        // The keyring updates need to be announced before updating the encryptionKey
        // so that the updated keyring gets propagated to the extension first.
        // Not calling _updateMemStoreKeyrings results in the wrong account being selected
        // in the extension.
        await this._updateMemStoreKeyrings();
        if (newEncryptionKey)
            this.memStore.updateState({ encryptionKey: newEncryptionKey });

        return !0;
    }

    /**
     * done
     * Update memStore Keyrings
     *
     * Updates the in-memory keyrings, without persisting.
     */
    async _updateMemStoreKeyrings() {
        const keyrings = await Promise.all(
            this.krings.map(this.displayForKeyring.bind(this)),
        );
        return this.memStore.updateState({ keyrings });
    }

    /**
     * done
     * Display For Keyring
     *
     * Is used for adding the current keyrings to the state object.
     *
     * @param {Keyring} keyring - The keyring to display.
     * @returns {Promise<object>} A keyring display object, with type and accounts properties.
     */
    async displayForKeyring(kring) {
        let accounts = [];
        const type = kring.type;
        accounts = await this.getAccounts(type);
        return { type, accounts };
    }

    /**
     * Submit password.
     * Attempts to decrypt the current vault and load its keyrings
     * into memory.
     * @fires KeyringController#unlock
     * @param {string} password - The keyring controller password.
     * @returns {Promise<object>} A Promise that resolves to the state.
     */
    async submitPassword(password) {
        this.krings = await this.unlockKrings(password);
        this.setUnlocked();
        return this.fullUpdate();
    }

    /**
     * Submit Encryption Key.
     * Attempts to decrypt the current vault and load its keyrings
     * into memory based on the vault and CryptoKey information.
     * @fires KeyringController#unlock
     * @param {string} encryptionKey - The encrypted key information used to decrypt the vault.
     * @param {string} encryptionSalt - The salt used to generate the last key.
     * @returns {Promise<object>} A Promise that resolves to the state.
     */
    async submitEncryptionKey(encryptionKey, encryptionSalt) {
        this.krings = await this.unlockKrings(
            undefined,
            encryptionKey,
            encryptionSalt,
        );
        this.setUnlocked();
        return this.fullUpdate();
    }

    /**
     * Set Locked
     * This method deallocates all secrets, and effectively locks MetaMask.
     * @fires KeyringController#lock
     * @returns {Promise<object>} A Promise that resolves to the state.
     */
    async setLocked() {
        delete this.password;

        // set locked
        this.memStore.updateState({
        isUnlocked: false,
        encryptionKey: null,
        encryptionSalt: null,
        });

        // remove keyrings
        this.krings = [];
        await this._updateMemStoreKeyrings();
        this.emit(EVENT.KRING.LOCK);
        return this.fullUpdate();
    }

    /**
     * Unlock Keyrings
     * Unlocks the keyrings.
     * @fires KeyringController#unlock
     */
    setUnlocked() {
        this.memStore.updateState({ isUnlocked: true });
        this.emit(EVENT.KRING.UNLOCK);
    }

    /**
     * Clear Keyrings
     * Deallocates all currently managed keyrings and accounts.
     * Used before initializing a new vault.
     */
    async clearKrings() {
        // clear keyrings from memory
        this.krings = [];
        this.memStore.updateState({
        keyrings: [],
        });
    }

    fullUpdate() {
        this.emit(EVENT.KRING.UPDATE, this.memStore.getState());
        return this.memStore.getState();
    }

    /**
     * Get Keyrings by Type
     * Gets all keyrings of the given type.
     * @param {string} type - The keyring types to retrieve.
     * @returns {Array<Keyring>} The keyrings.
     */
    getKringByType(type) {
        // log.i('[getKringByType] keyrings:', this.krings);
        return this.krings.filter(kring => kring.type === type)[0];
    }

    getKringBuilderForType(type) {
        return this.kringBuilders.find(
            builder => builder.type === type
        );
    }
}

function kringBuilder(Keyring, type) {
    const builder = () => new Keyring();
    builder.type = type;
    return builder;
}

export const testKring = async _ => {
    const p = new FireEvmKeyringsController({});
    await p.createNewVaultAndKeychain('scientist');
    let acc = await p.getAccounts(KEYRINGS_TYPE.EVM);
    log.i('[test] evm accs:', acc);
    acc = await p.getAccounts(KEYRINGS_TYPE.FIRE);
    log.i('[test] 5ire accs:', acc);
    await p.submitPassword('scientist');
    acc = await p.getAccounts(KEYRINGS_TYPE.EVM);
    log.i('[test] evm accs:', acc);
    acc = await p.getAccounts(KEYRINGS_TYPE.FIRE);
    log.i('[test] 5ire accs:', acc);
    await p.submitPassword('scientist1');
    acc = await p.getAccounts(KEYRINGS_TYPE.EVM);
    log.i('[test] evm accs:', acc);
    acc = await p.getAccounts(KEYRINGS_TYPE.FIRE);
    log.i('[test] 5ire accs:', acc);
}

function setListeners(o) {

}