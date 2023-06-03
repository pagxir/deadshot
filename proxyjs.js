const fs = require('fs');
const http = require('http');
const https = require('https');
const dgram = require('dgram');

const JS_VER = 10
const MAX_RETRY = 1

const PREFLIGHT_INIT = {
  status: 204,
  headers: {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
    'access-control-max-age': '1728000',
  }
};

const options = {
  key: fs.readFileSync('test/fixtures/keys/agent2-key.pem'),
  cert: fs.readFileSync('test/fixtures/keys/agent2-cert.pem')
};

function newUrl(urlStr) {
  try {
    return new URL(urlStr)
  } catch (err) {
    return null
  }
}

function makeRes(res, body, status = 200, headers = {}) {

  res.statusCode = status;
  for (const [k, v] of Object.entries(headers)) {
    res.setHeader(k, v);
  }

  res.end(body);
  return;
}

function formatName(name) {
  var parts = name.split('-');
  var retval = "";

  for (const part of parts) {
    if (retval !== "") retval += "-";
    retval += part.substr(0, 1).toUpperCase() + part.substr(1);
  }

  return retval;
}

function fetchAssetsEx(res, path, range) {
  const fsPath = path.substr(1);

  if (fsPath === "" ||  !fs.existsSync(fsPath)) {
    try {
      var data = fs.readFileSync("404.html", 'utf8');
      res.statusCode = 404;
      res.end(data); 
    } catch(e) {
      console.log('XError:', e.stack);
      res.end(); 
    }
    return;
  }

  const suffixes = path.substr(path.lastIndexOf('.'));

  console.log(suffixes);
  var mimeType = "application/octect-stream";
  switch(suffixes) {
    case ".js":
      mimeType = "text/javascript";
      break;
    case ".png":
      mimeType = "image/png";
      break;
    case ".txt":
      mimeType = "text/plain";
      break;
    case ".html":
      mimeType = "text/html";
      break;
  }

  res.setHeader("Content-Type", mimeType);

  try {
    var stats = fs.statSync(fsPath);
    var offset = parseInt(range[0]);

    console.log('XXX length: ' + stats.size);
    var contentRange = "bytes " + range[0] + "-" + (stats.size -1) + "/" + stats.size;

    res.setHeader("Content-Length", stats.size - offset);
    res.setHeader("Content-Range", contentRange);

    fs.createReadStream(fsPath, {start: offset}).pipe(res);
    res.statusCode = 206;
  } catch(e) {
    console.log('XError:', e.stack);
    res.statusCode = 404;
    res.end(); 
  }
}


function fetchAssets(res, path) {
  const fsPath = path.substr(1);

  if (fsPath === "" ||  !fs.existsSync(fsPath)) {
    try {
      var data = fs.readFileSync("404.html", 'utf8');
      res.statusCode = 404;
      res.end(data); 
    } catch(e) {
      console.log('XError:', e.stack);
      res.end(); 
    }
    return;
  }

  const suffixes = path.substr(path.lastIndexOf('.'));

  console.log(suffixes);
  var mimeType = "application/octect-stream";
  switch(suffixes) {
    case ".js":
      mimeType = "text/javascript";
      break;
    case ".png":
      mimeType = "image/png";
      break;
    case ".txt":
      mimeType = "text/plain";
      break;
    case ".html":
      mimeType = "text/html";
      break;
  }

  res.setHeader("Content-Type", mimeType);

  try {
    var stats = fs.statSync(fsPath);
    res.setHeader("Content-Length", stats.size);
    fs.createReadStream(fsPath).pipe(res);
  } catch(e) {
    console.log('XError:', e.stack);
    res.statusCode = 404;
    res.end(); 
  }
}

function urlRequest(url, options) {

  const reqInit = {
    method: options.method,
    headers: options.headers,
    highWaterMark: 1024000
  }

  console.log("request(" + url + ")");
  const handler = url.startsWith("http://")? http: https;

  return new Promise((resolv, reject) => {
    try {
      const cReq = handler.request(url, reqInit, (nRes) => resolv(nRes));
      cReq.on('error', reject);
      if (options.method === 'POST') {
        options.body.pipe(cReq);
      } else {
        cReq.end();
      }
    } catch (e) {
      reject(e);
    }
  });
}

async function request(aRes, url, options) {

  const reqInit = {
    method: options.method,
    headers: options.headers
  }

  const handler = url.startsWith("http://")? http: https;

  console.log("request(" + url + ")");
  const cReq = handler.request(url, reqInit,
    (nRes) => {

      for (const [k, v] of Object.entries(nRes.headers)) {
        console.log("key: " + k + " value: " + v);
        aRes.setHeader(k, v);
      }

      return nRes.pipe(aRes);
    }
  );

  if (options.method === 'POST') {
    options.body.pipe(cReq);
  } else {
    cReq.end();
  }
}

/**
 *
 * @param {URL} urlObj
 * @param {RequestInit} reqInit
 * @param {number} retryTimes
 */
async function proxy(urlObj, reqInit, acehOld, rawLen, retryTimes) {
  const res = await urlRequest(urlObj.href, reqInit)
  const resHdrNew = {};
  const resHdrOld = res.headers;

  let expose = '*'

  console.log("URL " + urlObj.href);
  for (const [k, v] of Object.entries(resHdrOld)) {
    if (k === 'access-control-allow-origin' ||
      k === 'access-control-expose-headers' ||
      k === 'location' ||
      k === 'set-cookie'
    ) {
      const x = '--' + k
      resHdrNew[x]=v
      if (acehOld) {
        expose = expose + ',' + x
      }
      // delete resHdrNew[k]
    }
    else if (acehOld &&
      k !== 'cache-control' &&
      k !== 'content-language' &&
      k !== 'content-type' &&
      k !== 'expires' &&
      k !== 'last-modified' &&
      k !== 'pragma'
    ) {
      expose = expose + ',' + k
      resHdrNew[k]=v
    } else {
      resHdrNew[k]=v
    }
  }

  if (acehOld) {
    expose = expose + ',--s'
    resHdrNew['--t']='1'
  }

  // verify
  if (rawLen) {
    const newLen = resHdrOld['content-length'] || ''
    const badLen = (rawLen !== newLen)

    if (badLen) {
      if (retryTimes < MAX_RETRY) {
        urlObj = await parseYtVideoRedir(urlObj, newLen, res)
        if (urlObj) {
          return proxy(urlObj, reqInit, acehOld, rawLen, retryTimes + 1)
        }
      }

      var props = {
        '--error': `bad len: ${newLen}, except: ${rawLen}`,
        'access-control-expose-headers': '--error',
      };

      res.statusCode = 400;

      for (const [k, v] of Object.entries(props)) {
        res.setHeader(k, v);
      }

      return res;
    }

    if (retryTimes > 1) {
      resHdrNew.set('--retry', retryTimes)
    }
  }

  let status = res.statusCode;

  resHdrNew['access-control-expose-headers'] = expose
  resHdrNew['access-control-allow-origin'] = '*'
  resHdrNew['--s'] = status
  resHdrNew['--ver'] = JS_VER

  delete resHdrNew['content-security-policy']
  delete resHdrNew['content-security-policy-report-only']
  delete resHdrNew['clear-site-data']

  if (status === 301 ||
    status === 302 ||
    status === 303 ||
    status === 307 ||
    status === 308
  ) {
    status = status + 10
  }

  res.statusCode = status;
  res.headers = resHdrNew;

  /*
  for (const [k, v] of Object.entries(resHdrNew)) {
    res.setHeader(k, v);
  }
  */

  return res;
}

async function httpHandler(aRes, req, pathname) {
  var headers = {};

  for (const [k, v] of Object.entries(req.headers)) {
    console.log("|key: " + k + " value: " + v);
    k === "host" || (headers[k] = v);
  }

  if (headers.hasOwnProperty('x-jsproxy')) {
    return makeRes(aRes, "internal error", 500);
  }

  let acehOld = false
  let rawSvr = ''
  let rawLen = ''
  let rawEtag = ''

  // preflight
  if (req.method === 'OPTIONS' &&
    headers.hasOwnProperty('access-control-request-headers')
  ) {
    return makeRes(res, "", 204, PREFLIGHT_INIT.headers);
  }

  const refer = headers.referer;
  const query = refer.substr(refer.indexOf('?') + 1)
  if (!query) {
    return makeRes(res, 'missing params', 403)
  }
  const param = new URLSearchParams(query)

  headers['x-jsproxy'] = '1';
  for (const [k, v] of param.entries()) {
    if (k.substr(0, 2) === '--') {
      // 系统信息
      switch (k.substr(2)) {
        case 'aceh':
          acehOld = true
          break
        case 'raw-info':
          [rawSvr, rawLen, rawEtag] = v.split('|')
          console.log("raw-info: " + v);
          break
      }
    } else {
      // 还原 HTTP 请求头
      if (v) {
        console.log("SET " + k + ":" + v);
        headers[k]=v
      } else {
        delete headers[k]
      }
    }
  }

  if (!param.has('referer')) {
    delete headers.referer
  }

  // cfworker 会把路径中的 `//` 合并成 `/`
  const urlStr = pathname.replace(/^(https?):\/+/, '$1://')
  const urlObj = newUrl(urlStr)
  if (!urlObj) {
    return makeRes(res, 'invalid proxy url: ' + urlStr, 403)
  }

  const reqInit0 = {
    method: req.method,
    headers: headers,
    body: req
  }

  const nRes = await proxy(urlObj, reqInit0, acehOld, rawLen, 0);

  for (const [k, v] of Object.entries(nRes.headers)) {
    console.log("key: " + k + " value: " + v);
    k === "alt-svc" || aRes.setHeader(k, v);
  }

  aRes.statusCode = nRes.statusCode;
  return nRes.pipe(aRes);
}

async function forwardHelper(aRes, req, url) {

  var headers = {};
  var urlObj = newUrl(url);

  for (const [k, v] of Object.entries(req.headers)) {
    console.log("|key: " + k + " value: " + v);
    headers[k] = v;
    (k === "host" || k === "Host") && (headers[k] = urlObj.host);
  }

  headers["referer"] && (headers["referer"] = headers["referer"].replace("v2x.yrli.bid", "www.v2ex.com"));

  const reqInit0 = {
    method: req.method,
    headers: headers,
    body: req
  }

  var nRes = await urlRequest(url, reqInit0);
  var redirect = nRes.statusCode === 302 || nRes.statusCode === 301;

  if (redirect) {
    for (const [k, v] of Object.entries(nRes.headers)) {
      if ((k === "location" || k === "Location") &&
        (v.startsWith("https://") || v.startsWith("http://"))) {
        var urlObj = newUrl(v);
        delete headers["host"];
        delete headers["Host"];
        headers["Host"] = urlObj.host;
        nRes = await urlRequest(v, reqInit0);
        break;
      }
    }
  }

  aRes.statusCode = nRes.statusCode;
  for (const [k, v] of Object.entries(nRes.headers)) {
    console.log("key: " + k + " value: " + v);
    if (k === "alt-svc") {
      console.log("ignore alt-svc" + v);
    } else  {
      aRes.setHeader(k, v);
    }
  }

  return nRes.pipe(aRes);
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

    client.send(finalBuffer, port, server, (err) => { console.log(`message: ${err}`); });
    return new Promise(cb);
}

async function fetchHandler(req, res) {
  let host = "";
  let refer = "";
  const path = req.url;

  for (const [k, v] of Object.entries(req.headers)) {
    k === "host" && (host = v);
    k === "refer" && (refer = v);
  }

  if (path.startsWith("/dns-query")) {
      var cb = b => {
          res.statusCode = 200;

          res.setHeader("Server", "cloudflare");
          res.setHeader("Date", new Date());
          res.setHeader("Content-Type", "application/dns-message");
          res.setHeader("Connection", "keep-alive");
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.setHeader("Content-Length", b.length);

          res.end(b);
      };

      const args = path.split("/");
      const host = args[2] || "8.8.8.8";
      const port = args[3] || 53;
      console.log("dns-query host: " + host + " port: " + port);

      if (req.method === "POST") return dns_query(req, host, port).then(cb);
      return forwardHelper(res, req, "https://cloudflare-dns.com" + path);
  }

  if (path.startsWith('/http/')) {
    return httpHandler(res, req, path.substr(6));
  }

  if (path.length > 15 && path.startsWith('/surfing.http/')) {
    return forwardHelper(res, req, "http://" + path.substr(14));
  }

  if (path.length > 15 && path.startsWith('/surfing.https/')) {
    return forwardHelper(res, req, "https://" + path.substr(15));
  }

  if (path.startsWith('/-----http') || path == '/') {
    return fetchAssets(res, "/404.html");
  }

  switch (path) {
    case '/http':
      return makeRes(res, '请更新 cfworker 到最新版本!')
    case '/ws':
      return makeRes(res, 'not support', 400)
    case '/works':
      return makeRes(res, 'it works')
    default:
      // static files
      if (path.indexOf(".") === -1)
        return makeRes(res, "not support", 400);


      if (req.headers["range"]) {
	  var rangestr = req.headers["range"];
	  console.log("range " + rangestr);
	  if (rangestr.startsWith("bytes=")) {
	      var ranges = rangestr.replace("bytes=", "").split("-");
	      console.log("range " + ranges);
	      if (ranges.length > 0) {
                  return fetchAssetsEx(res, path, ranges);
	      }
	  }
      }

      return fetchAssets(res, path);
  }
}

/**
 * @param {URL} urlObj 
 */
function isYtUrl(urlObj) {
  return (
    urlObj.host.endsWith('.googlevideo.com') &&
    urlObj.pathname.startsWith('/videoplayback')
  )
}

/**
 * @param {URL} urlObj 
 * @param {number} newLen 
 * @param {Response} res 
 */
async function parseYtVideoRedir(urlObj, newLen, res) {
  if (newLen > 2000) {
    return null
  }
  if (!isYtUrl(urlObj)) {
    return null
  }
  try {
    const data = await res.text()
    urlObj = new URL(data)
  } catch (err) {
    return null
  }
  if (!isYtUrl(urlObj)) {
    return null
  }
  return urlObj
}

async function doHttpRequest(req, res) {
    var path = req.url;
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

    if (path.startsWith("/surfing.http/")) {
        var hosts = path.split("/");
        headers["Host"] = host = hosts[2];

        var off = path.indexOf("/", 14);
        path = path.substr(off); 
        console.log("host = " + host + " path = " + path);
    }

    var requestOpt = {
	highWaterMark: 1024000,
	hostname: host,
	host: host,
	port: 80,
	path: path,
	setHost: true,
	method: req.method,
	headers: headers,
	body: req,
    };

    console.log("TODO:XXX Host:" + host + " Path:" + path + " type=" + JSON.stringify(headers));

    const cb = (resolv, reject) => {
	try {
	    const cReq = http.request(requestOpt, (nRes) => resolv(nRes));
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
    var redirect = nRes.statusCode === 302 || nRes.statusCode === 301;

    console.log("TODO:XXX: redirect " + redirect + " code=" + nRes.statusCode);
    if (redirect) {
	for (const [k, v] of Object.entries(nRes.headers)) {
	    if ((k === "location" || k === "Location") &&
		(v.startsWith("https://") || v.startsWith("http://"))) {
		var urlObj = newUrl(v);
		delete headers["host"];
		delete headers["Host"];
		headers["Host"] = urlObj.host;
		nRes = await urlRequest(v, requestOpt);
		break;
	    }
	}
    }

    res.statusCode = nRes.statusCode;

    key = "";
    for (const k of nRes.rawHeaders) {
        if (key === "") {
            key = k;
        } else {
            res.setHeader(key, k); key = "";
        }
    }

    console.log("XXXX: redirect finish");
    return nRes.pipe(res);
}

https.createServer(options, (req, res) => {
  // console.log(JSON.stringify(req.url));
  // console.log(JSON.stringify(req.headers));
  fetchHandler(req, res).catch(e => makeRes(res, "", 500));
}).listen(443);

