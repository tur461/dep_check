
const log = (_ => {
    return {
        i: function(){ console.log(...arguments) },
    }
})()

const toB64 = s => btoa(s);
const eHandle = e => e.preventDefault() || !0;
const isArr = a => a instanceof Array;
const isObj = o => typeof o === 'object';
const isStr = s => typeof s === 'string';
const isNum = s => typeof s === 'number';
const isFn = f => typeof f === 'function';
const isPrimitive = v => isNum(v) || isStr(v);

const jsnObj = s => JSON.parse(s);
const jsnStr = o => JSON.stringify(o);

const rEq = (a, b) => isStr(a) && isStr(b) ? a.toLowerCase() === b.toLowerCase() :
    isNum(a) && isNum(b) ? a === b :
    (isStr(a) && isNum(b)) || (isStr(b) && isNum(a)) ? a == b : !1; 

const notEq = (a ,b) => !rEq(a, b);

const isEmpty = v => isStr(v) || isArr(v) ? rEq(v.length, 0) :
    isObj(v) ? rEq(Object.entries(v).length, 0) : !1 ;

const notEmpty = v => !isEmpty(v);

const contains = (s, q) => notEq(s.toLowerCase().indexOf(q), -1);

const cloneDeep = v => isPrimitive(v)? v :
    isArr(v) ? v.map(vv => cloneDeep(vv)) :
    isObj(v) ? Object.keys(v).reduce((a, k) => {a[k] = cloneDeep(v[k]); return a}, {}) :
    v

const cloneShallow = v => isPrimitive(v) ? v : 
    isArr(v) ? [...v] :
    isObj(v) ? {...v} :
    v;

const noHexPrefix = v => v.slice(2);

const decAry2str = a => String.fromCharCode(...a);

const nullOrUndef = v => v === undefined || v === null;

const defOrNotNull = v => !nullOrUndef(v) && notEmpty(v);

const str2u8ary = s => (new TextEncoder()).encode(s);

// http version
const untilFinalized_HTTP = o => {
    let ivalGapms = 10;
    let ival = null;
    let op = {
        success: !1,
        result: null,
    };
    
    if(nullOrUndef(o.tx)) throw Error('transaction oject not given');
    if(nullOrUndef(o.signer)) throw Error('signer must be given');

    const p = o.params || [];
    const r = o.tx.signAndSend(o.signer, ...p, txHash => {
        // log.i('cbk r:', tx, tx.hash.toHex(), tx.toHex());
        // if(tx.isInBlock) return;
        if(txHash) {
            op.success = !0;
            op.result = txHash;
        }
        // if(tx.isError) return j(tx);
    })

    // log.i('internal result:', typeof r, r);
    return new Promise((r, j) => setInterval(_ => {
        if(defOrNotNull(op.result)) {
            clearInterval(ival);
            r(op);
        }
    }, ivalGapms));
}

// websocket version
const untilFinalized_WS = o => {
    let ivalGapms = 10;
    let ival = null;
    let op = {
        success: !1,
        result: null,
    };
    
    if(nullOrUndef(o.tx)) throw Error('transaction oject not given');
    if(nullOrUndef(o.signer)) throw Error('signer must be given');

    const p = o.params || [];
    o.tx.signAndSend(o.signer, ...p, tx => {
        // if(tx.isInBlock) return;
        if(tx.isFinalized) {
            op.success = !0;
            op.result = tx;
        } 
        // if(tx.isError) return j(tx);
    })
    
    return new Promise((r, j) => setInterval(_ => {
        if(defOrNotNull(op.result)) {
            clearInterval(ival);
            r(op);
        }
    }, ivalGapms));
}

const untilFinalized = o => untilFinalized_WS(o);

export {
    rEq,
    log,
    isFn,
    isStr,
    isNum,
    isArr,
    isObj,
    toB64,
    notEq,
    jsnObj,
    jsnStr,
    eHandle,
    isEmpty,
    notEmpty,
    contains,
    cloneDeep,
    str2u8ary,
    decAry2str,
    nullOrUndef,
    noHexPrefix,
    defOrNotNull,
    cloneShallow,
    untilFinalized,
}