var yauzl = require("../");
var crc32 = require("../crc32");

// Builds a minimal in-memory zipfile with arbitrary entry names so that
// collision attacks can be exercised without committing binary fixtures.
function buildZip(entries) {
  var chunks = [];
  var centralChunks = [];
  var offset = 0;
  entries.forEach(function(entry) {
    var nameBuffer = Buffer.from(entry.name, "utf8");
    var data = Buffer.from(entry.data == null ? "" : entry.data);
    var localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(entry.utf8 === false ? 0 : 0x800, 6); // flags
    localHeader.writeUInt16LE(0, 8); // stored
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0, 12); // mod date
    localHeader.writeUInt32LE(crc32(data), 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(nameBuffer.length, 26);
    localHeader.writeUInt16LE(0, 28);
    chunks.push(localHeader, nameBuffer, data);

    var centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(entry.utf8 === false ? 0 : 0x800, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc32(data), 16);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(nameBuffer.length, 28);
    centralHeader.writeUInt16LE(0, 30); // extra field length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk number
    centralHeader.writeUInt16LE(0, 36); // internal attributes
    centralHeader.writeUInt32LE(entry.name.charAt(entry.name.length - 1) === "/" ? 0x41ff0010 : 0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralChunks.push(centralHeader, nameBuffer);

    offset += localHeader.length + nameBuffer.length + data.length;
  });
  var centralStart = offset;
  var centralSize = centralChunks.reduce(function(total, chunk) { return total + chunk.length; }, 0);
  centralChunks.forEach(function(chunk) { chunks.push(chunk); });

  var end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(centralStart, 16);
  end.writeUInt16LE(0, 20);
  chunks.push(end);
  return Buffer.concat(chunks);
}

function openEntries(zipBuffer, options) {
  return new Promise(function(resolve, reject) {
    yauzl.fromBuffer(zipBuffer, Object.assign({lazyEntries: true}, options), function(err, zipfile) {
      if (err) return reject(err);
      var entries = [];
      zipfile.on("entry", function(entry) {
        entries.push(entry);
        zipfile.readEntry();
      });
      zipfile.on("error", reject);
      zipfile.on("end", function() { resolve(entries); });
      zipfile.readEntry();
    });
  });
}

function openError(zipBuffer, options) {
  return openEntries(zipBuffer, options).then(
    function() { throw new Error("expected the archive to be rejected"); },
    function(err) { return err.message; }
  );
}

var tests = [];
function test(name, fn) { tests.push({name: name, fn: fn}); }

test("case folding collision is rejected", function() {
  var zip = buildZip([{name: "Scanned.txt", data: "first"}, {name: "scanned.TXT", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/file name collision/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("case folding collision across directories is rejected", function() {
  var zip = buildZip([{name: "Dir/file.txt", data: "first"}, {name: "dir/FILE.TXT", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/file name collision/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("unicode normalization collision is rejected", function() {
  // e-acute as a single code point (NFC) vs. e + combining acute (NFD).
  var nfc = "caf\u00e9.txt";
  var nfd = "cafe\u0301.txt";
  var zip = buildZip([{name: nfc, data: "first"}, {name: nfd, data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/file name collision/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("windows reserved name is rejected", function() {
  var zip = buildZip([{name: "a.txt", data: "a"}, {name: "CON", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/windows reserved name/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("windows reserved name with extension is rejected", function() {
  var zip = buildZip([{name: "nul.txt", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/windows reserved name/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("file and directory with the same name collide", function() {
  var zip = buildZip([{name: "a", data: "scanned"}, {name: "a/", data: ""}, {name: "a/b.txt", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/file name collision/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("implicit parent directory collides with a prior file entry", function() {
  var zip = buildZip([{name: "a", data: "scanned"}, {name: "a/b.txt", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/file name collision/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("literal parent traversal is still rejected", function() {
  var zip = buildZip([{name: "../evil.txt", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/invalid relative path/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("trailing dot segment is rejected", function() {
  var zip = buildZip([{name: "legit.txt", data: "a"}, {name: "legit.txt.", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/trailing dot or space/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("illegal windows characters are rejected", function() {
  var zip = buildZip([{name: "bad:name.txt", data: "evil"}]);
  return openError(zip).then(function(message) {
    if (!/invalid characters in file name/.test(message)) throw new Error("wrong message: " + message);
  });
});

test("duplicate directory entries are allowed", function() {
  var zip = buildZip([{name: "a/"}, {name: "a/"}, {name: "a/b.txt", data: "ok"}]);
  return openEntries(zip).then(function(entries) {
    if (entries.length !== 3) throw new Error("expected 3 entries, got " + entries.length);
  });
});

test("legitimate unicode names are preserved and exposed via identity", function() {
  var name = "\u4e03\u4e2a\u623f\u95f4.txt";
  var zip = buildZip([{name: name, data: "ok"}]);
  return openEntries(zip).then(function(entries) {
    if (entries[0].fileName !== name) throw new Error("original name was modified: " + entries[0].fileName);
    if (entries[0].pathIdentity !== name.toLowerCase().normalize("NFC")) {
      throw new Error("unexpected pathIdentity: " + entries[0].pathIdentity);
    }
    if (JSON.stringify(entries[0].pathIdentitySegments) !== JSON.stringify([name.normalize("NFC").toLowerCase()])) {
      throw new Error("unexpected pathIdentitySegments: " + JSON.stringify(entries[0].pathIdentitySegments));
    }
  });
});

test("legitimate multi-directory archive keeps every original name", function() {
  var zip = buildZip([
    {name: "Turmion K\u00e4til\u00f6t/"},
    {name: "Turmion K\u00e4til\u00f6t/Hoitovirhe/"},
    {name: "Turmion K\u00e4til\u00f6t/Hoitovirhe/Rautaketju.mp3", data: "music"},
  ]);
  var expected = [
    "Turmion K\u00e4til\u00f6t/",
    "Turmion K\u00e4til\u00f6t/Hoitovirhe/",
    "Turmion K\u00e4til\u00f6t/Hoitovirhe/Rautaketju.mp3",
  ];
  return openEntries(zip).then(function(entries) {
    entries.forEach(function(entry, i) {
      if (entry.fileName !== expected[i]) throw new Error("name changed: " + entry.fileName);
    });
  });
});

test("collision check can be explicitly disabled", function() {
  var zip = buildZip([{name: "Scanned.txt", data: "first"}, {name: "scanned.txt", data: "evil"}]);
  return openEntries(zip, {validatePathIdentities: false}).then(function(entries) {
    if (entries.length !== 2) throw new Error("expected both entries");
    if (entries[0].pathIdentity !== null) throw new Error("identity should be absent when disabled");
  });
});

test("exported helpers behave as documented", function() {
  if (yauzl.validatePortableFileName("CON") == null) throw new Error("CON should be rejected");
  if (yauzl.validatePortableFileName("a/b.txt") != null) throw new Error("ordinary path should pass");
  var nfc = "caf\u00e9";
  var nfd = "cafe\u0301";
  if (yauzl.getPathIdentity(nfc) !== yauzl.getPathIdentity(nfd)) {
    throw new Error("NFC and NFD spellings must share an identity");
  }
  if (yauzl.getPathIdentity("Dir/File.TXT") !== "dir/file.txt") {
    throw new Error("identity must be case folded: " + yauzl.getPathIdentity("Dir/File.TXT"));
  }
  if (yauzl.getPathIdentitySegments("a/b/").length !== 2) {
    throw new Error("trailing directory slash must not add a segment");
  }
  return Promise.resolve();
});

exports.runTest = function(cb) {
  tests.reduce(function(promise, current) {
    return promise.then(function() {
      return current.fn().then(function() {
        console.log("path security: " + current.name + ": pass");
      });
    });
  }, Promise.resolve()).then(cb, cb);
};
