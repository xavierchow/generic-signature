'use strict';

const debug = require('debug')('generic-sign');
const crypto = require('crypto');

module.exports = function(param, options) {
  options = options || {};
  const stringA = Object.keys(param)
    .filter(key => (options.forceLowerCase ? key.toLowerCase() : key) !== options.excludedProp)
    .filter(key => param[key] != null && !isObject(param[key]))
    .map(key => `${options.forceLowerCase ? key.toLowerCase() : key}=${param[key]}`)
    .sort()
    .join('&');
  const signTemp = `${stringA}&key=${options.key}`;
  debug(signTemp);

  const algorithm = options.algorithm || 'md5';
  let signed = crypto.createHash(algorithm).update(signTemp, 'utf8').digest('hex');
  if (options.resultToUpperCase) {
    signed = signed.toUpperCase();
  }
  return signed;
};

function isObject(obj) {
  return obj === Object(obj);
}
