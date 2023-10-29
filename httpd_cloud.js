const fs = require('fs');
const http = require('http');
const https = require('https');
const dgram = require('dgram');
const dnspacket = require('dns-packet');

function dns_nomalize(data) {

  if (data.additionals) {

    var opt_map = item => {
      if (!item.options) return item;

      item.options = item.options.filter(item => !item.type || item.type != "PADDING");
      return item;
    };

    data.additionals = data.additionals.map(opt_map);
  }

  return data;
}

function dns_inject(packet, ip) {
    var message = dns_nomalize(dnspacket.decode(packet));
    console.log("response: " + JSON.stringify(message));

    var cb = item => {
        if (item.type == 'A' && isInOverseaNet(item.data)) {
            item.data = ip;
        }
        return item;
    };

    message.answers = message.answers.map(cb);
    return dnspacket.encode(message);
}

function dns_client_subnet(data, clientip) {

    var parts = clientip.split(".");
    var clientipstr = parts[0] + "." + parts[1] + "." + parts[2] + ".0";
        console.log("clientipstr " + clientipstr);
    var additionals0 = {"name":".","type":"OPT","udpPayloadSize":4096,"extendedRcode":0,"ednsVersion":0,"flags":0,"flag_do":false,"options":[{"code":8,"type":"CLIENT_SUBNET","family":1,"sourcePrefixLength":24,"scopePrefixLength":22,"ip":clientipstr}]};

  if (data.questions && !data.questions.find(item => item.type == 'A')) {
      return data;
  }

  if (data.additionals) {
    var injected = false;

    var opt_map = item => {
      if (!item.options) return item;

      if (item.name == '.' && item.type == "OPT") {
        item.options = item.options.filter(item => !item.type || item.type != "CLIENT_SUBNET");
        item.options.push(additionals0.options[0]);
        injected = true;
      }

      return item;
    };

    data.additionals = data.additionals.map(opt_map);
    if (!injected) data.additionals.push(additionals0);
  }

  return data;
}

function makeRes(res, body, status = 200, headers = {}) {

    res.statusCode = status;
    for (const [k, v] of Object.entries(headers)) {
        res.setHeader(k, v);
    }

    res.end(body);
    return;
}

async function dns_query(message, server, port)
{
    const client = dgram.createSocket('udp4');

    const buffers = [];
    for await (const data of message) {
        buffers.push(data);
    }

    const finalBuffer = Buffer.concat(buffers);

    var cb = (resolv, reject) => {
        client.on('error', (err) => { console.error(`server error:\n${err.stack}`); client.close(); });
        client.on('message', (msg, rinfo) => { console.log(`server got: ${rinfo.address}:${rinfo.port}`); resolv(msg); client.close(); clearTimeout(client.timer); });
	client.timer = setTimeout(v => { client.close(); reject(); }, 3300);
    };

    var message = dns_nomalize(dnspacket.decode(finalBuffer));
    var packet  = dnspacket.encode(dns_client_subnet(message, clientip));
    console.log("query " + JSON.stringify(message));

    client.send(finalBuffer, port, server, (err) => { console.log(`message: ${err}`); });
    return new Promise(cb);
}


/*
 *
 *if (path.startsWith('/surfing.http/')) {
 *  var okurl =  "http://" + path.substr(14);
 *  var headers = req.headers;
 *  delete headers["Host"];

 *  const reqInit = {method: req.method, headers: headers, redirect: 'manual',}
 *  if (req.method === 'POST') {
 *     reqInit.body = req.body
 *  }

 *  const res = await fetch(okurl, reqInit);
 *  return new Response(res.body, {status: res.status, headers: res.headers,});
 *}
 *
 */

const AGENT_HOST = "app.yrli.bid";
async function doHttpRequest(req, res) {
    const path = req.url;
    let host = "www.baidu.com";

    for (const [k, v] of Object.entries(req.headers)) {
	k === "host" && (host = v);
    }

    var key = "";
    var headers = {};

    for (const k of req.rawHeaders) {
	if (key === "") {
	    key = k;
	} else {
	    headers[key] = k;
	    key = "";
	}
    }

    var dns_cb = b => {
	res.statusCode = 200;

	res.setHeader("Server", "cloudflare");
	res.setHeader("Date", new Date());
	res.setHeader("Content-Type", "application/dns-message");
	res.setHeader("Connection", "keep-alive");
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Content-Length", b.length);

	res.end(b);
    };

    if (path.startsWith("/dns-query") && req.method === "POST") {
	const args = path.split("/");
	const host = args[2] || "8.8.8.8";
	const port = args[3] || 53;
	console.log("dns-query host: " + host + " port: " + port);

	return dns_query(req, host, port).then(dns_cb);
    }

    const URL = "https://" + AGENT_HOST + "/surfing.http/" + host + path;
    headers["Host"] = AGENT_HOST;

    console.log("URL " + URL);
    console.log("Host:" + host + " Path:" + path + " type=" + JSON.stringify(headers));

    var requestOpt = {
	highWaterMark: 1024000,
	hostname: AGENT_HOST,
	host: AGENT_HOST,
	path: "/surfing.http/" + host + path,
	setHost: true,
	method: req.method,
	headers: headers,
	body: req,
    };

    const cb = (resolv, reject) => {
	try {
	    const cReq = https.request(requestOpt, (nRes) => resolv(nRes));
	    cReq.on('error', reject);
	    if (options.method === 'POST') {
		options.body.pipe(cReq);
	    } else {
		cReq.end();
	    }
	} catch (e) {
	    reject(e);
	}
    };

    var nRes = await new Promise(cb);

    res.statusCode = nRes.statusCode;

    key = "";
    for (const k of nRes.rawHeaders) {
        if (key === "") {
            key = k;
        } else {
            res.setHeader(key, k); key = "";
        }
    }

    return nRes.pipe(res);
}

const options = {};
const httpd = (req, res) => {
    doHttpRequest(req, res).catch(e => makeRes(res, e, 500));
}

http.createServer(options, httpd).listen(8080);
