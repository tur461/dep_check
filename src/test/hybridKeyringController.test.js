import { notEq } from "../common";
import { KEYRINGS_TYPE } from "../Constants/hdwallet";
import FireEvmKeyringsController from "../libs/FireEvmKeyringsController";
import { log } from "../utils/common";

runAll().then().catch(console.error);

async function runAll() {
    await newKring();
}



async function newKring() {
    const inst = getInst();
    kring = inst._newKring(KEYRINGS_TYPE.EVM);
    if(!kring.type || notEq(kring.type, KEYRINGS_TYPE.EVM)) 
        throw Error('no keyring created!!');
    log.i('_newKring works!!');
}


function getInst() {
    return new FireEvmKeyringsController();
}