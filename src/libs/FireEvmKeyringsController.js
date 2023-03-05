const { EventEmitter } = require('events');
const ObservableStore = require('obs-store');
const pHdKeyring = require('@polkadot/keyring');
const { EVENT } = require('../Constants/events');
const pUtilCrypto = require('@polkadot/util-crypto');
const mHdKeyring = require('@metamask/eth-hd-keyring');
const mEncryptor = require('@metamask/browser-passworder');
const { KEYRINGS_TYPE, ERR_STR, CRPT_SCHEME } = require('../Constants/hdwallet');
const { 
    log,
    rEq,
    isFn,
    isStr,
    jsnStr,
    isEmpty,
    str2u8ary,
    nullOrUndef,
    noHexPrefix,
    defOrNotNull,
} = require('../utils/common');
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
        this.mnemonic = opts.mnemonic || null;
        this.krings = [];
        this._unsupportedKrings = [];
        // This option allows the controller to cache an exported key
        // for use in decrypting and encrypting data without password
        this.cacheEncryptionKey = Boolean(opts.cacheEncryptionKey);

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
        this.setUnlocked();
        return this.fullUpdate();
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

        const hexAccount = normalizeAddress(evmFirstAcc);
        this.emit(
            EVENT.NEW_VAULT, { 
                evmAccount: hexAccount, 
                fireAccount: fireFirstAcc 
            });
        this.setUnlocked();
        return this.fullUpdate();
    }

    async signTransaction(type, tx, fromAddr, opts = {}) {
        // const fromAddr = normalizeAddress(_fromAddress);
        const kring = await this.getKringByAddr(type, fromAddr);
        let signedTx = '';
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            signedTx = await kring.signTransaction(fromAddr, tx, opts);
        } else {
            // handle for polkadot

        }
        return signedTx;
    }

    async signMessage(type, msgParams) {
        if(nullOrUndef(this.password)) throw Error(ERR_STR.FAILURE_PWD_LOCKED);
        const address = normalizeAddress(msgParams.from);
        let sig = '';
        const m = msgParams.data;
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            if(nullOrUndef(this.krings[0])) throw Error(ERR_STR.ADD_EVM_ACC_FAILURE_KRNG);
            sig = await this.krings[0].signMessage(address, m);
        } else {
            if(nullOrUndef(this.krings[1])) throw Error(ERR_STR.ADD_FIRE_ACC_FAILURE_KRNG);
            sig = await this.sign(isStr(m) ? str2u8ary(m) : m);
        }
        return sig;
    }

    async addNewKrings(opts = {}) {
        let evmKring = null, fireKring = null; 
        if(defOrNotNull(opts.password) && defOrNotNull(opts.mnemonic)) {
            this.password = opts.password;
            this.mnemonic = opts.mnemonic;
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
            // createNewVaultAndKeychain -> createFirstKeyTree -> addNewKrings
            evmKring = await this._newKring(KEYRINGS_TYPE.EVM);
            fireKring = await this._newKring(KEYRINGS_TYPE.FIRE);
            // Generate & save mnemonic for the future usage
            this.mnemonic = this.getNewRandomMnemonic();
            log.i('[addNewKrings]', this.mnemonic);
            evmKring._initFromMnemonic(this.mnemonic);
            await this._addNewFireAccount(fireKring);
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
                this.mnemonic = vault.mnemonic;

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
            this.mnemonic = vault.mnemonic;
        }

        await Promise.all(vault.krings.map(this._restoreKring.bind(this)));
        await this._updateMemStoreKrings();
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
            this._unsupportedKrings.push(serialized);
            return undefined;
        }

        // getAccounts also validates the accounts for some keyrings
        if(rEq(type, KEYRINGS_TYPE.EVM)) await keyring.getAccounts();
        this.krings.push(keyring);
        log.i(type, data);
        // add accounts one less as first one would have been created already
        for(
            let i = 0; 
            i < data.numberOfAccounts - 1; 
            await (
                rEq(type, KEYRINGS_TYPE.EVM) ? 
                keyring.addAccounts() : 
                this._addNewFireAccount(keyring)
            ),
            ++i
        );
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
        const kringBuilder = this.getKringBuilderForType(type);
    
        if (!kringBuilder) return undefined;
    
        const kring = kringBuilder();
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            await kring.deserialize(data);
            if (kring.init) await kring.init();
        } else await this._addNewFireAccount(kring)
    
        return kring;
    }
    // done
    // success when submitPassword() has been called or wallet unlocked 
    async addNewAccount() {
        if(nullOrUndef(this.password)) throw Error(ERR_STR.FAILURE_PWD_LOCKED);
        if(nullOrUndef(this.mnemonic)) throw Error(ERR_STR.ADD_5IRE_ACC_FAILURE_MNC);
        if(nullOrUndef(this.krings[0])) throw Error(ERR_STR.ADD_EVM_ACC_FAILURE_KRNG);
        if(nullOrUndef(this.krings[1])) throw Error(ERR_STR.ADD_FIRE_ACC_FAILURE_KRNG);
        await this.krings[0].addAccounts();
        await this._addNewFireAccount(this.krings[1]);
        await this.persistAllKrings();
        this.emit(EVENT.KRING.ACC_ADDED);
    }

    // success when submitPassword() has been called or wallet unlocked
    async removeAccount(type, addr) {
        if(nullOrUndef(this.password)) throw Error(ERR_STR.FAILURE_PWD_LOCKED);
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            if(nullOrUndef(this.krings[0])) throw Error(ERR_STR.ADD_EVM_ACC_FAILURE_KRNG);
            if(isFn(this.krings[0].removeAccount)) await this.krings[0].removeAccount(addr);
            else log.i();
        } else {
            if(nullOrUndef(this.mnemonic)) throw Error(ERR_STR.ADD_5IRE_ACC_FAILURE_MNC);
            if(nullOrUndef(this.krings[1])) throw Error(ERR_STR.ADD_FIRE_ACC_FAILURE_KRNG);
            await this.krings[1].removePair(addr);
        }
        this.emit(EVENT.KRING.ACC_REMOVED);
    }

    // success when submitPassword() has been called or wallet unlocked
    async exportPvtKey(type, addr, pass) {
        if(nullOrUndef(this.password)) throw Error(ERR_STR.FAILURE_PWD_LOCKED);
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            if(nullOrUndef(this.krings[0])) throw Error(ERR_STR.ADD_EVM_ACC_FAILURE_KRNG);
            if(isFn(this.krings[0].exportAccount)) await this.krings[0].exportAccount(addr);
            else log.i();
        } else {
            if(nullOrUndef(this.mnemonic)) throw Error(ERR_STR.ADD_5IRE_ACC_FAILURE_MNC);
            if(nullOrUndef(this.krings[1])) throw Error(ERR_STR.ADD_FIRE_ACC_FAILURE_KRNG);
            // await this.krings[1].removePair(addr);

        }
    }

    // done
    // check for duplicate accounts by checking just first 1
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
        
        const vaultPlain = {
            krings: [
                {
                    type: this.krings[0].type,
                    data: evmSer,
                },
                {
                    type: this.krings[1].type,
                    data: {
                        hdPath: this.memStore.getState().hdPath,
                        numberOfAccounts: this.krings[1].pairs.length,
                    }
                }
            ],
            mnemonic: this.mnemonic,
        }
        // log.i('[persistAllKrings] vaultPlain:', vaultPlain);
        let vault;
        let newEncryptionKey;

        if (this.cacheEncryptionKey) {
            if (this.password) {
                const { vault: newVault, exportedKeyString } =
                await this.encryptor.encryptWithDetail(
                    this.password,
                    vaultPlain,
                );

                vault = newVault;
                newEncryptionKey = exportedKeyString;
            } else if (encryptionKey) {
                const key = await this.encryptor.importKey(encryptionKey);
                const vaultJSON = await this.encryptor.encryptWithKey(
                    key,
                    vaultPlain,
                );
                vaultJSON.salt = encryptionSalt;
                vault = jsnStr(vaultJSON);
            }
        } else {
            // log.i('[persistAllKrings]', this.password, vaultPlain);
            vault = await this.encryptor.encrypt(this.password, vaultPlain);
        }

        if (!vault) throw new Error(ERR_STR.NO_VAULT_INFO);

        this.store.updateState({ vault });

        // The keyring updates need to be announced before updating the encryptionKey
        // so that the updated keyring gets propagated to the extension first.
        // Not calling _updateMemStoreKrings results in the wrong account being selected
        // in the extension.
        await this._updateMemStoreKrings();
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
    async _updateMemStoreKrings() {
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
        log.i('submitPassword() called');
        this.krings = await this.unlockKrings(password);
        log.i('submit password about to return', this.krings);
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
        delete this.mnemonic;

        // set locked
        this.memStore.updateState({
            isUnlocked: false,
            encryptionKey: null,
            encryptionSalt: null,
        });

        // remove keyrings
        this.krings = [];
        await this._updateMemStoreKrings();
        this.emit(EVENT.KRING.LOCK);
        return this.fullUpdate();
    }

    /**
     * Clear Keyrings
     * Deallocates all currently managed keyrings and accounts.
     * Used before initializing a new vault.
     */
    async clearKrings() {
        // clear keyrings from memory
        this.krings = [];
        this.memStore.updateState({ keyrings: [] });
    }

    async _addNewFireAccount(kring) {
        const uri = this.getFireUriStr();
        log.i('[_addNewFireAccount]', uri);
        await kring.addFromUri(uri, {}, CRPT_SCHEME.SR);
        this.updateFireHdPath();
    }

    async getKringByAddr(type, addr) {
        if(nullOrUndef(this.password)) throw Error(ERR_STR.FAILURE_PWD_LOCKED);
        let kring = null;
        if(rEq(type, KEYRINGS_TYPE.EVM)) {
            this.krings[0].filter(kr => kr);
        } else {

        }
        return kring;
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

    // done
    getFireAccounts() {
        const kring = this.getKringByType(KEYRINGS_TYPE.FIRE);
        return kring.getPairs().map(p => p.address);
    }

    getFireUriStr() {
        return `${this.mnemonic}//${this.memStore.getState().hdPath}`;
    }

    updateFireHdPath() {
        this.memStore.updateState({
            hdPath: this.memStore.getState().hdPath + 1
        });
    }

    getNewRandomMnemonic() {
        return pUtilCrypto.mnemonicGenerate().trim()
    }

    getMnemonic(pass) {
        let mn = null;
        if(defOrNotNull(this.password)) {
            if(rEq(this.password, pass)) mn = this.mnemonic;
        } else {

        }
        return this.mnemonic;
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