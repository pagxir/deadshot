const tls = require('tls');
const fs = require('fs');
const net = require('net');
const dgram = require('dgram');
const dnsp = require('dns-packet');
const assert = require('assert');

const options = {
  key: fs.readFileSync('certificate/tls.key'),
  cert: fs.readFileSync('certificate/fullchain.cer'),
  requestCert: false,
  ca: [ fs.readFileSync('certificate/ca.cer') ]
};

let dumpFirst = 0;

function dnsSendQuery(client, message) {

  var cb = (resolv, reject) => {
    client.on('error', reject);
    client.on('message', resolv);
    client.timer = setTimeout(reject, 3300);
  };

  let port = 53;
  let server = "::ffff:1.0.0.1";

  client.send(message, port, server, (err) => { if (err) console.log(`message: ${err}`); });
  return new Promise(cb);
}

function dnsDispatchQuery(socket, message) {
  const client = dgram.createSocket('udp6');

  const dnsResult = result => {
    if (dumpFirst)
      console.log("dnsResult " + JSON.stringify(dnsp.decode(result).questions[0]));
    else
      console.log("dnsResult " + JSON.stringify(dnsp.decode(result)));

    dumpFirst=1;
    let b = Buffer.alloc(2);
    b.writeUInt16BE(result.length);

    socket.write(b);
    socket.write(result);
    client.close();
  };

  const onFailure = result => {
    let response;
    let fragment = dnsp.decode(message);

    fragment.type = "response";
    response = dnsp.encode(fragment);

    let b = Buffer.alloc(2);
    b.writeUInt16BE(response.length);

    socket.write(b);
    socket.write(response);
    client.close();
    console.log("onFailure " + JSON.stringify(fragment.questions[0]));
  };

  const data = dnsp.decode(message);
  console.log("QUERY " + JSON.stringify(dnsp.decode(message).questions[0]));
  return dnsSendQuery(client, message).then(dnsResult, onFailure);
}

async function handleRequest(socket) {

  let total = 0;
  let segsize = 0;
  let buffers = [];
  let lastbuf = Buffer.alloc(0);
  let ended = false;

  let onTimeout = v => {
    if (!ended) {
      ended = true;
    } else {
      socket.destroy();
    }
  };

  let timer = setInterval(onTimeout, 15000);

  console.log('FROM ' + socket.remoteAddress + " port=" + socket.remotePort);
  for await (const data of socket) {
    total += data.length;

    if (data.length < 2) {
      lastbuf += data;
    } else {
      buffers.push(data);
    }
   
    console.log('FROM ' + socket.remoteAddress + " port=" + socket.remotePort + " data=" + data.length);
    lastbuf = data;
    ended = false;
    while (total >= 2) {

      segsize = buffers[0].readUInt16BE();
      if (segsize + 2 > total) {
	break;
      }

      const stream = Buffer.concat(buffers);

      buffers = [];
      total -= (segsize + 2);
      lastbuf = Buffer.alloc(0);

      if (total > 0) {
	lastbuf = stream.slice(segsize + 2);
	buffers.push(lastbuf);
      }

      try {
         await dnsDispatchQuery(socket, stream.slice(2, segsize + 2));
      } catch(e) {
	 console.log("error " + e);
      }

      ended = false;
    }
  }

  console.log("session ended");
  if (!ended) socket.end();
  clearInterval(timer);
  // socket.end();
}

const server = tls.createServer(options, (socket) => {
  console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
  const address = socket.remoteAddress;
  socket.on("error", e => console.log("error " + e));
  socket.on("close", e => socket.end());
  handleRequest(socket);
});

server.listen(853, () => {
  console.log('server bound');
});

const tcpserver = net.createServer(options, (socket) => {
  const address = socket.remoteAddress;
  socket.on("error", e => console.log("error " + e));
  socket.on("close", e => socket.end());
  handleRequest(socket);
});

tcpserver.listen(8853, () => {
  console.log('server bound');
});
