// Tests for streaming CRC-32 content authentication and the semantics of
// early cancel, byte ranges, raw mode, and encrypted entries.
var yauzl = require("../");
var zlib = require("zlib");
var stream = require("stream");

exports.runTest = runTest;

function makeZip(method, content, options) {
  options = options || {};
  var name = Buffer.from("file.txt");
  var flags = options.encrypted ? 0x1 : 0;
  var crc = options.crc32 != null ? options.crc32 : (zlib.crc32(content) >>> 0);
  var payload = method === 8 ? zlib.deflateRawSync(content) : content;
  var uncompressedSize = options.uncompressedSize != null ? options.uncompressedSize : content.length;

  var local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(flags, 6); // general purpose bit flag
  local.writeUInt16LE(method, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(payload.length, 18);
  local.writeUInt32LE(uncompressedSize, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);

  var central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(flags, 8); // general purpose bit flag
  central.writeUInt16LE(method, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt16LE(0, 14);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(payload.length, 20);
  central.writeUInt32LE(uncompressedSize, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);

  var eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length + name.length, 12);
  eocd.writeUInt32LE(local.length + name.length + payload.length, 16);
  eocd.writeUInt16LE(0, 20);

  return {
    buffer: Buffer.concat([local, name, payload, central, name, eocd]),
    fileDataStart: local.length + name.length,
    payload: payload,
  };
}

function openFirstEntry(zipBuffer, zipOptions) {
  return new Promise(function(resolve, reject) {
    yauzl.fromBuffer(zipBuffer, Object.assign({lazyEntries: true}, zipOptions || {}), function(err, zipfile) {
      if (err) return reject(err);
      zipfile.readEntry();
      zipfile.on("error", reject);
      zipfile.on("entry", function(entry) { resolve({zipfile: zipfile, entry: entry}); });
    });
  });
}

function collectStream(readStream) {
  return new Promise(function(resolve, reject) {
    var chunks = [];
    readStream.on("data", function(chunk) { chunks.push(chunk); });
    readStream.on("error", reject);
    readStream.on("end", function() { resolve(Buffer.concat(chunks)); });
  });
}

function expectStreamError(prefix, readStream) {
  return new Promise(function(resolve, reject) {
    var ended = false;
    readStream.on("data", function() {});
    readStream.on("error", function(err) {
      // Tampered deflate data may be rejected by zlib before the CRC stage.
      // Either way, tampered content must never produce a clean "end".
      if (!/CRC-32 mismatch/.test(err.message) &&
          !/zlib|inflate|code lengths|distance|literal|end of file|invalid/i.test(err.message)) {
        return reject(new Error(prefix + "expected an integrity error, got: " + err.message));
      }
      resolve(err.message);
    });
    readStream.on("end", function() {
      ended = true;
      reject(new Error(prefix + "tampered content was reported as a successful end"));
    });
  });
}

async function runTest(cb) {
  try {
    var content = Buffer.from("the quick brown fox jumps over the lazy dog".repeat(50));

    // Stored and deflated entries, each with a tampered payload of identical length.
    for (var method of [0, 8]) {
      var label = method === 0 ? "stored" : "deflated";
      var fixture = makeZip(method, content);
      fixture.buffer[fixture.fileDataStart + 3] ^= 0xff;
      var opened = await openFirstEntry(fixture.buffer);
      await new Promise(function(resolve, reject) {
        opened.zipfile.openReadStream(opened.entry, function(err, readStream) {
          if (err) return reject(err);
          expectStreamError("crc tampered " + label + ": ", readStream).then(function() {
            console.log("crc tampered " + label + ": pass");
            resolve();
          }, reject);
        });
      });
    }

    // A deflated payload that inflates fine but does not match the declared CRC.
    var liar = makeZip(8, Buffer.from("totally different contents here!!!"), {
      crc32: zlib.crc32(content) >>> 0,
    });
    var liarOpened = await openFirstEntry(liar.buffer);
    await new Promise(function(resolve, reject) {
      liarOpened.zipfile.openReadStream(liarOpened.entry, function(err, readStream) {
        if (err) return reject(err);
        expectStreamError("crc lying deflate: ", readStream).then(function() {
          console.log("crc lying deflate: pass");
          resolve();
        }, reject);
      });
    });

    // A tiny stored entry whose source ends synchronously (fromBuffer) must
    // still deliver the integrity error on the readStream instead of throwing
    // an unhandled "error" event before listeners can be attached.
    var tinyStoredFixture = makeZip(0, Buffer.from("x"));
    tinyStoredFixture.buffer[tinyStoredFixture.fileDataStart] ^= 0xff;
    var tinyStoredZipfile = await new Promise(function(resolve, reject) {
      yauzl.fromBuffer(tinyStoredFixture.buffer, {lazyEntries: true}, function(err, zipfile) {
        if (err) return reject(err);
        resolve(zipfile);
      });
    });
    await new Promise(function(resolve, reject) {
      tinyStoredZipfile.readEntry();
      tinyStoredZipfile.on("entry", function(tinyEntry) {
        tinyStoredZipfile.openReadStream(tinyEntry, function(err, readStream) {
          if (err) return reject(err);
          expectStreamError("tiny stored: ", readStream).then(function() {
            console.log("tiny stored synchronous-end error: pass");
            resolve();
          }, reject);
        });
      });
    });

    // Same timing guarantee for a tiny deflated entry that inflates fine but
    // declares a bogus CRC in the central directory.
    var tinyDeflateFixture = makeZip(8, Buffer.from("x"), {crc32: 0xdeadbeef});
    var tinyDeflateZipfile = await new Promise(function(resolve, reject) {
      yauzl.fromBuffer(tinyDeflateFixture.buffer, {lazyEntries: true}, function(err, zipfile) {
        if (err) return reject(err);
        resolve(zipfile);
      });
    });
    await new Promise(function(resolve, reject) {
      tinyDeflateZipfile.readEntry();
      tinyDeflateZipfile.on("entry", function(tinyEntry) {
        tinyDeflateZipfile.openReadStream(tinyEntry, function(err, readStream) {
          if (err) return reject(err);
          expectStreamError("tiny deflated: ", readStream).then(function(message) {
            if (!/CRC-32 mismatch/.test(message)) {
              return reject(new Error("tiny deflated expected a CRC error, got: " + message));
            }
            console.log("tiny deflated synchronous-end error: pass");
            resolve();
          }, reject);
        });
      });
    });

    // Legit files read cleanly, both stored and deflated.
    for (var goodMethod of [0, 8]) {
      var goodLabel = goodMethod === 0 ? "stored" : "deflated";
      var goodFixture = makeZip(goodMethod, content);
      var goodOpened = await openFirstEntry(goodFixture.buffer);
      await new Promise(function(resolve, reject) {
        goodOpened.zipfile.openReadStream(goodOpened.entry, function(err, readStream) {
          if (err) return reject(err);
          collectStream(readStream).then(function(data) {
            if (!data.equals(content)) throw new Error("valid " + goodLabel + " contents mismatch");
            console.log("valid " + goodLabel + " full read: pass");
            resolve();
          }, reject);
        });
      });
    }

    // Early cancel: destroy() must not raise a CRC error for an unfinished read.
    var cancelFixture = makeZip(0, content);
    var cancelOpened = await openFirstEntry(cancelFixture.buffer);
    await new Promise(function(resolve, reject) {
      cancelOpened.zipfile.openReadStream(cancelOpened.entry, function(err, readStream) {
        if (err) return reject(err);
        var seen = 0;
        var cancelled = false;
        readStream.on("data", function(chunk) {
          seen += chunk.length;
          if (!cancelled && seen >= content.length / 4) {
            cancelled = true;
            readStream.unpipe();
            readStream.destroy();
          }
        });
        readStream.on("error", function(err) {
          reject(new Error("early cancel produced an error: " + err.message));
        });
        readStream.on("close", function() {
          if (!cancelled) return reject(new Error("stream closed before destroy() was called"));
          console.log("early cancel: pass");
          resolve();
        });
      });
    });

    // Byte ranges: a tampered range is delivered raw without a CRC verdict,
    // because the CRC only authenticates the complete decoded entry.
    var rangeFixture = makeZip(0, content);
    rangeFixture.buffer[rangeFixture.fileDataStart + 5] ^= 0xff;
    var rangeOpened = await openFirstEntry(rangeFixture.buffer);
    await new Promise(function(resolve, reject) {
      rangeOpened.zipfile.openReadStream(rangeOpened.entry, {start: 2, end: 10}, function(err, readStream) {
        if (err) return reject(err);
        collectStream(readStream).then(function(data) {
          var expected = content.slice(2, 10);
          expected[5 - 2] ^= 0xff; // reflect the tampered byte inside the range
          if (!data.equals(expected)) throw new Error("range read returned wrong bytes");
          console.log("range read skips crc: pass");
          resolve();
        }, reject);
      });
    });

    // Raw mode (decodeFileData: false) returns encoded bytes without a CRC verdict.
    var rawFixture = makeZip(8, content);
    var expectedRawPayload = Buffer.from(rawFixture.payload);
    rawFixture.buffer[rawFixture.fileDataStart + 1] ^= 0xff;
    var rawOpened = await openFirstEntry(rawFixture.buffer);
    await new Promise(function(resolve, reject) {
      rawOpened.zipfile.openReadStream(rawOpened.entry, {decodeFileData: false}, function(err, readStream) {
        if (err) return reject(err);
        collectStream(readStream).then(function(data) {
          var tamperedExpected = Buffer.from(expectedRawPayload);
          tamperedExpected[1] ^= 0xff;
          if (!data.equals(tamperedExpected)) throw new Error("raw read returned wrong bytes");
          console.log("raw mode skips crc: pass");
          resolve();
        }, reject);
      });
    });

    // The deprecated decompress bypass has the same raw semantics.
    var bypassOpened = await openFirstEntry(makeZip(8, content).buffer);
    await new Promise(function(resolve, reject) {
      bypassOpened.zipfile.openReadStream(bypassOpened.entry, {decompress: false}, function(err, readStream) {
        if (err) return reject(err);
        collectStream(readStream).then(function() {
          console.log("deprecated decompress bypass skips crc: pass");
          resolve();
        }, reject);
      });
    });

    // Encrypted entries are delivered raw; yauzl cannot decode them, so no CRC verdict.
    // The fake 12-byte traditional-encryption header keeps the stored-size
    // validation happy: compressed size = uncompressed size + 12.
    var encryptedContent = Buffer.concat([Buffer.alloc(12), content]);
    var encryptedFixture = makeZip(0, encryptedContent, {
      encrypted: true,
      uncompressedSize: content.length,
    });
    var encryptedOpened = await openFirstEntry(encryptedFixture.buffer);
    await new Promise(function(resolve, reject) {
      encryptedOpened.zipfile.openReadStream(encryptedOpened.entry, {decodeFileData: false}, function(err, readStream) {
        if (err) return reject(err);
        collectStream(readStream).then(function(data) {
          if (!data.equals(encryptedContent)) throw new Error("encrypted raw read returned wrong bytes");
          console.log("encrypted raw read skips crc: pass");
          resolve();
        }, reject);
      });
    });

    // validateEntrySizes: false also disables CRC authentication, matching
    // the opt-out for the other stream-level integrity checks.
    var optOutFixture = makeZip(0, content);
    optOutFixture.buffer[optOutFixture.fileDataStart + 2] ^= 0xff;
    var optOutOpened = await openFirstEntry(optOutFixture.buffer, {validateEntrySizes: false});
    await new Promise(function(resolve, reject) {
      optOutOpened.zipfile.openReadStream(optOutOpened.entry, function(err, readStream) {
        if (err) return reject(err);
        collectStream(readStream).then(function() {
          console.log("validateEntrySizes false skips crc: pass");
          resolve();
        }, reject);
      });
    });

    // Large entry: authentication must stay streaming (no whole-file buffering).
    var bigContent = Buffer.alloc(5 * 1024 * 1024);
    for (var i = 0; i < bigContent.length; i++) bigContent[i] = (i * 31 + 7) & 0xff;
    var bigFixture = makeZip(8, bigContent);
    var bigOpened = await openFirstEntry(bigFixture.buffer);
    await new Promise(function(resolve, reject) {
      bigOpened.zipfile.openReadStream(bigOpened.entry, function(err, readStream) {
        if (err) return reject(err);
        var received = 0;
        var maxChunkBuffered = 0;
        var sink = new stream.Writable({
          write: function(chunk, encoding, callback) {
            received += chunk.length;
            maxChunkBuffered = Math.max(maxChunkBuffered, chunk.length);
            callback();
          },
        });
        sink.on("finish", function() {
          if (received !== bigContent.length) return reject(new Error("large read size mismatch"));
          if (maxChunkBuffered > 128 * 1024) {
            return reject(new Error("expected chunked streaming, got a chunk of " + maxChunkBuffered + " bytes"));
          }
          console.log("large file streamed without buffering: pass");
          resolve();
        });
        sink.on("error", reject);
        readStream.on("error", reject);
        readStream.pipe(sink);
      });
    });

    cb();
  } catch (err) {
    cb(err);
  }
}

if (require.main === module) {
  runTest(function(err) {
    if (err) throw err;
    console.log("all done");
  });
}
