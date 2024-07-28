const fs = require('fs');
const http = require('http');
const https = require('https');

const options = {};

function makeRes(res, body, status = 200, headers = {}) {
    res.statusCode = status;

    for (const [k, v] of Object.entries(headers)) {
	res.setHeader(k, v);
    }

    res.end(body);
    return;
}


const AGENT_HOST = "cdn.603030.xyz";

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

    const URL = "https://" + AGENT_HOST + "/surfing.http/" + host + path;
    headers["Host"] = AGENT_HOST;
    headers["host"] = AGENT_HOST;

    console.log("URL " + URL);
    console.log("Host:" + host + " Path:" + path + " header=" + JSON.stringify(headers));

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

http.createServer(options, (req, res) => {
    doHttpRequest(req, res).catch(e => makeRes(res, "", 500));
}).listen(8080);

