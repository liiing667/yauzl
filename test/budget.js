// Tests for the session expansion budget: maxTotalUncompressedSize and maxCompressionRatio.
// The zip files are generated at runtime so that metadata can be forged to lie about sizes.

var fs = require("fs");
var os = require("os");
var path = require("path");
var zlib = require("zlib");
var yauzl = require("../");
var crc32 = typeof zlib.crc32 === "function" ? zlib.crc32 : require("../crc32");

exports.runTest = runTest;

function runTest(callback) {
  var tests = [
    testNormalMultiFileArchiveWithinBudget,
    testDeclaredCompressionRatioBomb,
    testDeclaredCumulativeSizeBomb,
    testStreamRatioBombCancelledMidDecompression,
    testStreamCumulativeSizeCancelledMidDecompression,
    testInvalidBudgetOptions,
  ];
  var i = 0;
  next();
  function next() {
    if (i === tests.length) return callback();
    tests[i++](function() {
      process.stdout.write("budget: " + tests[i - 1].name + ": pass\n");
      next();
    });
  }
}

// A normal multi-file archive must still extract when a generous budget is configured.
function testNormalMultiFileArchiveWithinBudget(cb) {
  var entries = [
    {name: "a.txt", data: Buffer.from("hello world\n")},
    {name: "b.txt", data: Buffer.from("the quick brown fox jumps over the lazy dog\n".repeat(100))},
    {name: "c.bin", data: pseudoRandomBytes(4096), compress: false},
  ];
  openZip(entries, {
    lazyEntries: true,
    maxTotalUncompressedSize: 1024 * 1024,
    maxCompressionRatio: 100,
  }, function(err, zipfile) {
    if (err) throw err;
    var actualContents = {};
    zipfile.readEntry();
    zipfile.on("entry", function(entry) {
      zipfile.openReadStream(entry, function(err, readStream) {
        if (err) throw err;
        var buffers = [];
        readStream.on("data", function(data) { buffers.push(data); });
        readStream.on("end", function() {
          actualContents[entry.fileName] = Buffer.concat(buffers);
          zipfile.readEntry();
        });
        readStream.on("error", function(err) { throw err; });
      });
    });
    zipfile.on("end", function() {
      entries.forEach(function(entry) {
        if (actualContents[entry.name] == null) throw new Error("missing entry: " + entry.name);
        if (actualContents[entry.name].toString("binary") !== entry.data.toString("binary")) {
          throw new Error("wrong contents for entry: " + entry.name);
        }
      });
      cb();
    });
    zipfile.on("error", function(err) { throw err; });
  });
}

// A zip bomb that honestly declares an absurd compression ratio
// must be rejected from its metadata before any decompression happens.
function testDeclaredCompressionRatioBomb(cb) {
  openZip([
    {name: "bomb.txt", data: Buffer.alloc(1024 * 1024, 0x61)},
  ], {
    lazyEntries: true,
    maxCompressionRatio: 10,
  }, function(err, zipfile) {
    if (err) throw err;
    expectSessionFailure(zipfile, /maxCompressionRatio/, cb);
    zipfile.readEntry();
  });
}

// Many small entries whose declared sizes add up past the session total
// must be stopped at the entry that crosses the budget.
function testDeclaredCumulativeSizeBomb(cb) {
  openZip([
    {name: "1.txt", data: Buffer.alloc(100, 0x31)},
    {name: "2.txt", data: Buffer.alloc(100, 0x32)},
    {name: "3.txt", data: Buffer.alloc(100, 0x33)},
  ], {
    lazyEntries: true,
    maxTotalUncompressedSize: 250,
  }, function(err, zipfile) {
    if (err) throw err;
    var entryNames = [];
    zipfile.on("entry", function(entry) {
      entryNames.push(entry.fileName);
      zipfile.readEntry();
    });
    expectSessionFailure(zipfile, /maxTotalUncompressedSize/, function() {
      if (entryNames.join(",") !== "1.txt,2.txt") {
        throw new Error("expected the first two entries to be emitted, got: " + entryNames);
      }
      cb();
    });
    zipfile.readEntry();
  });
}

// An entry that lies about its uncompressed size in its metadata
// must be cancelled mid-decompression once the actual ratio blows up.
function testStreamRatioBombCancelledMidDecompression(cb) {
  var realData = Buffer.alloc(4 * 1024 * 1024, 0x61);
  openZip([
    {name: "long-tail.bin", data: realData, declaredUncompressedSize: 100},
  ], {
    lazyEntries: true,
    validateEntrySizes: false,
    maxCompressionRatio: 5,
  }, function(err, zipfile) {
    if (err) throw err;
    zipfile.on("entry", function(entry) {
      zipfile.openReadStream(entry, function(err, readStream) {
        if (err) throw err;
        var bytesReceived = 0;
        var streamEnded = false;
        readStream.on("data", function(data) { bytesReceived += data.length; });
        readStream.on("end", function() { streamEnded = true; });
        readStream.on("error", function(err) {
          if (!/maxCompressionRatio/.test(err.message)) throw err;
          if (streamEnded) throw new Error("stream emitted end before error");
          if (bytesReceived >= realData.length) {
            throw new Error("decompression was not cancelled mid-stream");
          }
        });
      });
    });
    expectSessionFailure(zipfile, /maxCompressionRatio/, cb);
    zipfile.readEntry();
  });
}

// Entries that each look small but collectively emit more than the session total
// must be cancelled mid-decompression on the entry that crosses the budget.
function testStreamCumulativeSizeCancelledMidDecompression(cb) {
  openZip([
    {name: "1.bin", data: Buffer.alloc(1024 * 1024, 0x31), declaredUncompressedSize: 10},
    {name: "2.bin", data: Buffer.alloc(1024 * 1024, 0x32), declaredUncompressedSize: 10},
  ], {
    lazyEntries: true,
    validateEntrySizes: false,
    maxTotalUncompressedSize: 1536 * 1024,
  }, function(err, zipfile) {
    if (err) throw err;
    var streamErrors = 0;
    zipfile.on("entry", function(entry) {
      zipfile.openReadStream(entry, function(err, readStream) {
        if (err) throw err;
        readStream.on("data", function(data) {});
        readStream.on("end", function() {
          zipfile.readEntry();
        });
        readStream.on("error", function(err) {
          if (!/maxTotalUncompressedSize/.test(err.message)) throw err;
          streamErrors += 1;
        });
      });
    });
    expectSessionFailure(zipfile, /maxTotalUncompressedSize/, function() {
      if (streamErrors !== 1) throw new Error("expected exactly one stream error, got: " + streamErrors);
      cb();
    });
    zipfile.readEntry();
  });
}

function testInvalidBudgetOptions(cb) {
  var threw = 0;
  [ {maxTotalUncompressedSize: -1},
    {maxTotalUncompressedSize: "lots"},
    {maxCompressionRatio: -1},
    {maxCompressionRatio: NaN},
  ].forEach(function(options) {
    try {
      yauzl.fromBuffer(buildZip([{name: "a.txt", data: Buffer.from("a")}]), options, function() {});
    } catch (err) {
      threw += 1;
    }
  });
  if (threw !== 4) throw new Error("expected invalid budget options to throw");
  cb();
}

// Builds a zip file from the given entries, writes it to a temporary file,
// and opens it with yauzl.open (so autoClose and "close" events behave normally).
// The temporary file is removed once the zipfile closes.
function openZip(entries, options, callback) {
  var zipBuffer = buildZip(entries);
  var zipfilePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "yauzl-budget-")), "test.zip");
  fs.writeFileSync(zipfilePath, zipBuffer);
  yauzl.open(zipfilePath, options, function(err, zipfile) {
    if (err) {
      cleanup();
      return callback(err);
    }
    zipfile.on("close", cleanup);
    callback(null, zipfile);
  });
  function cleanup() {
    fs.rmSync(path.dirname(zipfilePath), {recursive: true, force: true});
  }
}

// Asserts that the zipfile session fails with an error matching the pattern
// and never reaches a completed ("end") state.
function expectSessionFailure(zipfile, errorPattern, onFailed) {
  var gotError = false;
  zipfile.on("error", function(err) {
    if (gotError) throw new Error("multiple errors emitted");
    gotError = true;
    if (!errorPattern.test(err.message)) throw err;
  });
  zipfile.on("end", function() {
    throw new Error("zipfile emitted end after the budget was exceeded");
  });
  zipfile.on("close", function() {
    if (!gotError) throw new Error("zipfile closed without emitting a budget error");
    // let any stray events fire before declaring success
    setImmediate(onFailed);
  });
}

// deterministic pseudo-random bytes so the fixture is stable
function pseudoRandomBytes(length) {
  var state = 0x2f6e2b1;
  var buffer = Buffer.alloc(length);
  for (var i = 0; i < length; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    buffer[i] = state & 0xff;
  }
  return buffer;
}

// Builds a minimal zip file in memory.
// entries: [{name, data, compress (default true), declaredUncompressedSize, declaredCompressedSize}]
function buildZip(entries) {
  var chunks = [];
  var centralDirectory = [];
  var offset = 0;
  entries.forEach(function(entry) {
    var compress = entry.compress !== false;
    var nameBuffer = Buffer.from(entry.name, "utf8");
    var compressedData = compress ? zlib.deflateRawSync(entry.data) : entry.data;
    var compressedSize = entry.declaredCompressedSize != null ? entry.declaredCompressedSize : compressedData.length;
    var uncompressedSize = entry.declaredUncompressedSize != null ? entry.declaredUncompressedSize : entry.data.length;
    var crc = crc32(entry.data);

    var localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4); // version needed to extract
    localHeader.writeUInt16LE(0x800, 6); // general purpose bit flag: utf8
    localHeader.writeUInt16LE(compress ? 8 : 0, 8); // compression method
    localHeader.writeUInt16LE(0, 10); // last mod file time
    localHeader.writeUInt16LE(0, 12); // last mod file date
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressedSize, 18);
    localHeader.writeUInt32LE(uncompressedSize, 22);
    localHeader.writeUInt16LE(nameBuffer.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra field length
    chunks.push(localHeader, nameBuffer, compressedData);

    var centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed to extract
    centralHeader.writeUInt16LE(0x800, 8); // general purpose bit flag: utf8
    centralHeader.writeUInt16LE(compress ? 8 : 0, 10); // compression method
    centralHeader.writeUInt16LE(0, 12); // last mod file time
    centralHeader.writeUInt16LE(0, 14); // last mod file date
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressedSize, 20);
    centralHeader.writeUInt32LE(uncompressedSize, 24);
    centralHeader.writeUInt16LE(nameBuffer.length, 28);
    // extra field length, file comment length, disk number start,
    // internal file attributes, external file attributes all 0
    centralHeader.writeUInt32LE(offset, 42); // relative offset of local header
    centralDirectory.push(centralHeader, nameBuffer);

    offset += localHeader.length + nameBuffer.length + compressedData.length;
  });
  var centralDirectoryBuffer = Buffer.concat(centralDirectory);
  var eocdr = Buffer.alloc(22);
  eocdr.writeUInt32LE(0x06054b50, 0);
  // number of this disk, disk with central directory: 0
  eocdr.writeUInt16LE(entries.length, 8); // entries on this disk
  eocdr.writeUInt16LE(entries.length, 10); // total entries
  eocdr.writeUInt32LE(centralDirectoryBuffer.length, 12);
  eocdr.writeUInt32LE(offset, 16); // offset of central directory
  // comment length: 0
  return Buffer.concat(chunks.concat([centralDirectoryBuffer, eocdr]));
}

if (require.main === module) {
  runTest(function() {
    console.log("all budget tests pass");
  });
}
