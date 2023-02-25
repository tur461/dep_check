const ERR_STR = {
    PWD_NOT_TEXT: 'Password must be text.',
    NO_PREV_ENC_VAULT: 'Cannot unlock without a previous vault.',
    NO_VAULT_INFO: 'Cannot persist vault without vault information',
    PERSIST: 'Cannot persist vault without password and encryption key',
    KEY_AND_SALT_XPIRED: 'Encryption key and salt provided are expired',
    NO_EVM_ACC: 'KeyringController - No EVM account found on keychain.',
    NO_EVM_FIRST_ACC: 'KeyringController - EVM First Account not found.',
    NO_FIRE_ACC: 'KeyringController - No 5IRE account found on keychain.',
    NO_FIRE_FIRST_ACC: 'KeyringController - 5IRE First Account not found.',
    ADD_ACC_FAILURE_PWD: 'password is null/not defined, new account or accounts could not be added.',
    ADD_EVM_ACC_FAILURE_KRNG: 'keyring not defined, new EVM account or accounts could not be added.',
    ADD_FIRE_ACC_FAILURE_KRNG: 'keyring not defined, new 5IRE account or accounts could not be added.',
    ADD_5IRE_ACC_FAILURE_MNC: 'mnemonic is null/not defined, new 5IRE account or accounts could not be added',
}
const CHAIN_TYPE = {
    EVM: 'ethereum_chain',
    FIRE: 'substrate_chain',
}


const KEYRINGS_TYPE = {
    EVM: 'HD Key Tree',
    FIRE: 'ed25519',
    FIRE_DEF: 'sr25519',
  };

export {
    ERR_STR,
    CHAIN_TYPE,
    KEYRINGS_TYPE,
}