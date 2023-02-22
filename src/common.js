
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

export {
    rEq,
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
    noHexPrefix,
    cloneShallow,
}
