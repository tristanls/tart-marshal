/*

dos.js - denial-of-service attack regression test

The MIT License (MIT)

Copyright (c) 2013 Dale Schumacher, Tristan Slominski

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
var marshal = require('../index.js');
var tart = require('tart-stepping');

var test = module.exports = {};

test['default receptionist should not create proxies for unknown inbound addresses'] = function (test) {
    test.expect(1);

    var network = marshal.router();
    var domain = marshal.domain('tcp://localhost:1000/', network.transport);

    try {
        domain.receptionist({
            address: 'tcp://localhost:1000/#doesnotexist',
            content: '"boom!"'
        });
    } catch (error) {
        test.equal(error.message,
            "Unknown address: tcp://localhost:1000/#doesnotexist");
    }

    test.done();
};

test['default receptionist throws when decryption fails'] = function (test) {
    test.expect(1);
    var stepping = tart.stepping();
    var sponsor = stepping.sponsor;

    var network = marshal.router();
    var domain = network.domain('ocap:zero');

    var actor = sponsor(function () {});

    var remote = domain.localToRemote(actor);
    var parsed = remote.split('#');
    var address = parsed[0] + '#' + parsed[1].split('?')[0];

    var message = {
        address,
        content: 'definitely not encrypted',
        nonce: crypto.randomBytes(10).toString("base64")
    };
    try {
        domain.receptionist(message);
    } catch (error) {
        test.equal(error.message, "Decryption failed: " + JSON.stringify(message));
    }

    test.done();
};
