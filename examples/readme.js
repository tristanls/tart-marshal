/*

readme.js - example from the README

The MIT License (MIT)

Copyright (c) 2013 Dale Schumacher

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

var tart = require('tart');
var marshal = require('../index.js');

var sponsor0 = tart.minimal();
var sponsor1 = tart.minimal();

var pingBeh = function pingBeh(message) {
    if (message.value === undefined) {
        var pong = message.pong;
        pong({ ping:this.self, pong:pong, value:0 });
    } else {
        console.log('ping', message.value);
    }
};

var pongBeh = function pongBeh(message) {
    var ping = message.ping;
    ping({ ping:ping, pong:this.self, value:1 });
    console.log('pong', message.value);
};

var ping = sponsor0(pingBeh);
var pong = sponsor1(pongBeh);

var proxyCaps = marshal.proxy(pong);
var pongProxy = sponsor0(proxyCaps.proxyBeh);
var pongStub = sponsor1(proxyCaps.stubBeh);

ping({ pong:pongProxy });
