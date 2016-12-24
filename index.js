/*

index.js - "tart-marshal": Send messages between memory domains (tart module)

The MIT License (MIT)

Copyright (c) 2013-2016 Dale Schumacher, Tristan Slominski

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

*/
"use strict";

var crypto = require("crypto");
var encryption = require("sodium-encryption");
var marshal = module.exports;

var KEY_LENGTH_IN_BYTES = encryption.key().length;
var NONCE_LENGTH_IN_BYTES = encryption.nonce().length;

marshal.randomBytes = crypto.randomBytes;

marshal.defaultRoute = function route(message) {
    throw Error('No route for ' + message.address);
};

marshal.router = function router(defaultRoute) {  // table-based routing transport
    var self = {};

    self.defaultRoute = defaultRoute || marshal.defaultRoute;

    self.routingTable = {};  // mapping from domains to transports

    self.transport = function transport(message) {
        // { address:<token>, content:<base64>, nonce:<base64> }
        var remote = message.address;
        var parsed = remote.split('#');
        if (parsed.length != 2) { throw Error('Bad address format: ' + remote); }
        var domain = parsed[0];
        var route = self.routingTable[domain];
        if (!route) {
            route = self.defaultRoute;
        }
        route(message);
    };

    self.domain = function domain(name) {
        var dom = marshal.domain(name, self.transport);
        self.routingTable[dom.name] = function route(message) {
            dom.receptionist(message);  // call domain endpoint
        };
        return dom;
    };

    return self;
};

marshal.domain = function domain(name, transport) {
    var self = {};
    var tokenMap = {};

    self.receptionist = function endpoint(message) {
        // { address:<token>, content:<base64>, nonce:<base64> }
        var local = tokenMap[message.address] && tokenMap[message.address].local;
        if (!local) { throw Error('Unknown address: ' + message.address); }
        var nonceBuffer = Buffer.from(message.nonce, "base64");
        var nonce = nonceBuffer.slice(0, NONCE_LENGTH_IN_BYTES);
        var ephemeralPublicKey = nonceBuffer.slice(NONCE_LENGTH_IN_BYTES);
        var sharedKey, plaintext;
        try {
            sharedKey = encryption.scalarMultiplication(tokenMap[message.address].keyPair.secretKey, ephemeralPublicKey);
            plaintext = encryption.decrypt(Buffer.from(message.content, "base64"), nonce, sharedKey).toString("utf8");
        } catch (error) {
            throw Error('Decryption failed: ' + JSON.stringify(message));
        }
        local(decode(plaintext));
    };

    var bindLocal = function bindLocal(remote, keyPair, local) {
        tokenMap[remote] = {
            keyPair,
            local
        };
        var parsed = remote.split('#');
        var address = parsed[0] + '#' + parsed[1].split('?')[0];
        tokenMap[address] = tokenMap[remote];
    };

    var localToRemote = function localToRemote(local) {
        var remote;
        for (remote in tokenMap) {
            if (tokenMap[remote] && tokenMap[remote].local === local) {
                return remote;
            }
        }
        /* not found, create a new entry */
        var keyPair = encryption.scalarMultiplicationKeyPair(marshal.randomBytes(KEY_LENGTH_IN_BYTES));
        remote = generateToken(keyPair.publicKey);
        bindLocal(remote, keyPair, local);
        return remote;
    };
    var generateToken = function generateToken(publicKey) {
        return self.name + '#' + generateCapability() + '?' + publicKey.toString('base64');
    };
    var generateCapability = function generateCapability() {
        return marshal.randomBytes(42).toString('base64');
    };

    var remoteToLocal = function remoteToLocal(remote) {
        var local = tokenMap[remote] && tokenMap[remote].local;
        if (local === undefined) {
            var parsed = remote.split('?');
            if (parsed.length != 2) { throw Error('Bad address format: ' + remote); }
            var address = parsed[0];
            var remotePublicKey = Buffer.from(parsed[1], 'base64');
            local = newProxy(address, remotePublicKey);  // create new proxy function
            bindLocal(remote, { publicKey: remotePublicKey }, local);
        }
        return local;
    };
    var newProxy = function newProxy(address, remotePublicKey) {
        return function proxy(message) {
            var ephemeralKeyPair = encryption.scalarMultiplicationKeyPair(marshal.randomBytes(KEY_LENGTH_IN_BYTES));
            var sharedKey = encryption.scalarMultiplication(ephemeralKeyPair.secretKey, remotePublicKey);
            var nonce = marshal.randomBytes(NONCE_LENGTH_IN_BYTES);
            self.transport({
                address,
                content: encryption.encrypt(Buffer.from(encode(message), "utf8"), nonce, sharedKey).toString("base64"),
                nonce: Buffer.concat([nonce, ephemeralKeyPair.publicKey]).toString("base64")
            });
        };
    };

    var encode = function encode(message) {
        return JSON.stringify(message, replacer);
    };
    var replacer = function replacer(key, value) {
        if (typeof value === 'function') {
            return localToRemote(value);
        }
        if (typeof value === 'string') {
            return encodeString(value);
        }
        if (value instanceof Error) {
            return {
                message: value.message,
                stack: value.stack
            };
        }
        return value;
    };
    var encodeString = function encodeString(value) {
        return ":" + value;
    };

    var decode = function decode(json) {
        if (json === undefined) {
            return undefined;
        }
        return JSON.parse(json, reviver);
    };
    var reviver = function reviver(key, value) {
        if (typeof value === 'string') {
            if (isString(value)) {
                return decodeString(value);
            } else {
                return remoteToLocal(value);
            }
        }
        return value;
    };
    var isString = function isString(value) {
        return (value.charAt(0) === ":");
    };
    var decodeString = function decodeString(value) {
        return value.slice(1);
    };

    var generateName = function generateName(name) {
        if (!name) {
            name = 'ansible://' + generateCapability() + '/';
        }
        return name;
    };

    self.name = generateName(name);
    self.transport = transport || marshal.defaultRoute;
    self.encode = encode;
    self.decode = decode;
    self.localToRemote = localToRemote;
    self.remoteToLocal = remoteToLocal;
    self.bindLocal = bindLocal;
    return self;
};
