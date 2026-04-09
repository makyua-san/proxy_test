const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const CERTS_DIR = path.join(__dirname, '..', 'data', 'certs');
const CA_KEY_PATH = path.join(CERTS_DIR, 'ca.key.pem');
const CA_CERT_PATH = path.join(CERTS_DIR, 'ca.pem');

fs.mkdirSync(CERTS_DIR, { recursive: true });

const certCache = new Map();
let caKey = null;
let caCert = null;

function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function initCA() {
  if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
    caKey = forge.pki.privateKeyFromPem(fs.readFileSync(CA_KEY_PATH, 'utf8'));
    caCert = forge.pki.certificateFromPem(fs.readFileSync(CA_CERT_PATH, 'utf8'));
    return;
  }

  const { privateKey, publicKey } = generateKeyPair();
  caKey = forge.pki.privateKeyFromPem(privateKey);
  const caPublicKey = forge.pki.publicKeyFromPem(publicKey);

  caCert = forge.pki.createCertificate();
  caCert.publicKey = caPublicKey;
  caCert.serialNumber = '01';
  caCert.validity.notBefore = new Date();
  caCert.validity.notAfter = new Date();
  caCert.validity.notAfter.setFullYear(caCert.validity.notAfter.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: 'Proxy Test CA' },
    { name: 'organizationName', value: 'Proxy Test Tool' }
  ];
  caCert.setSubject(attrs);
  caCert.setIssuer(attrs);
  caCert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true, critical: true }
  ]);
  caCert.sign(caKey, forge.md.sha256.create());

  fs.writeFileSync(CA_KEY_PATH, forge.pki.privateKeyToPem(caKey));
  fs.writeFileSync(CA_CERT_PATH, forge.pki.certificateToPem(caCert));
}

function getHostCert(hostname) {
  if (certCache.has(hostname)) return certCache.get(hostname);

  const { privateKey, publicKey } = generateKeyPair();
  const hostPublicKey = forge.pki.publicKeyFromPem(publicKey);

  const cert = forge.pki.createCertificate();
  cert.publicKey = hostPublicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true }
  ]);
  cert.sign(caKey, forge.md.sha256.create());

  const result = {
    key: privateKey,
    cert: forge.pki.certificateToPem(cert)
  };
  certCache.set(hostname, result);
  return result;
}

function getCACertPath() {
  return CA_CERT_PATH;
}

initCA();

module.exports = { getHostCert, getCACertPath };
