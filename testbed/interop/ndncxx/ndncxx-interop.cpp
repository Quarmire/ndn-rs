// ndncxx-interop: ndn-cxx 0.9 checks of ndn-rs certificates and Data.
// Built and driven by check.sh (next to this file).
//
//   ndncxx-interop [--key-name-locators] inspect FILE...
//   ndncxx-interop [--key-name-locators] validate --anchor FILE [--cert FILE]... TARGET
//
// Input files: raw TLV wire (first byte 0x06) or base64 text (ndnsec format).
// Every check prints a line starting with PASS/FAIL/UNSUPPORTED/NOTE/INFO.
// --key-name-locators: a KeyLocator must name the signer's key
// (/<id>/KEY/<key-id>); one naming a certificate is a FAIL (ndn-rs signers
// always name the key).
// Exit status: 0 when no FAIL line was printed, 1 otherwise, 2 on usage error.

#include <ndn-cxx/data.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/certificate-fetcher-offline.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/validation-policy-config.hpp>
#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <vector>

using namespace ndn;
using security::Certificate;

static int g_failures = 0;
static bool g_keyNameLocators = false;

static void
report(const std::string& status, const std::string& what)
{
  if (status == "FAIL")
    ++g_failures;
  std::cout << status << ": " << what << std::endl;
}

static Block
loadBlock(const std::string& path)
{
  std::ifstream is(path, std::ios::binary);
  if (!is)
    throw std::runtime_error("cannot open " + path);
  std::string bytes((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
  if (!bytes.empty() && static_cast<uint8_t>(bytes[0]) == tlv::Data) {
    return Block(make_span(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()));
  }
  std::istringstream ss(bytes);
  auto buf = io::loadBuffer(ss, io::BASE64);
  return Block(buf);
}

static Data
loadData(const std::string& path)
{
  return Data(loadBlock(path));
}

// KeyLocator form: "key" (/<id>/KEY/<key-id>), "cert" (/<id>/KEY/<key-id>/<issuer>/<version>),
// or "" (neither). ndn-rs names the key; ndn-cxx 0.9 signers name a certificate.
static std::string
keyLocatorForm(const Name& n)
{
  if (n.size() >= 2 && n.get(-2) == Certificate::KEY_COMPONENT)
    return "key";
  if (Certificate::isValidName(n))
    return "cert";
  return "";
}

static int
sigType(const Data& d)
{
  return d.getSignatureType();
}

static std::string
sigTypeStr(int t)
{
  std::ostringstream os;
  os << static_cast<tlv::SignatureTypeValue>(t);
  return os.str();
}

// Ed25519 public key from certificate content: SPKI DER or raw 32 bytes.
static EVP_PKEY*
ed25519Key(span<const uint8_t> content)
{
  if (content.size() == 32)
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, content.data(), content.size());
  const unsigned char* p = content.data();
  EVP_PKEY* k = d2i_PUBKEY(nullptr, &p, static_cast<long>(content.size()));
  if (k != nullptr && EVP_PKEY_get_id(k) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(k);
    return nullptr;
  }
  return k;
}

static std::string
describePublicKey(const Certificate& cert)
{
  auto content = cert.getPublicKey();
  try {
    security::transform::PublicKey pk;
    pk.loadPkcs8(content);
    if (pk.getKeyType() != KeyType::NONE) {
      std::ostringstream os;
      os << pk.getKeyType() << " (" << content.size() << "-byte SPKI)";
      return os.str();
    }
  }
  catch (const std::exception&) {
  }
  if (EVP_PKEY* k = ed25519Key(content)) {
    EVP_PKEY_free(k);
    return content.size() == 32 ? "Ed25519 (raw 32-byte key, not SPKI)" : "Ed25519 (SPKI)";
  }
  return "";
}

// Verify `data`'s signature with the key in `signer`. Returns nullopt when the
// signature type is not verifiable here.
static std::optional<bool>
verifyWith(const Data& data, const Certificate& signer, std::string& note)
{
  int t = sigType(data);
  if (t == tlv::SignatureSha256WithEcdsa || t == tlv::SignatureSha256WithRsa) {
    note = "ndn-cxx verifySignature";
    return security::verifySignature(data, std::optional<Certificate>(signer));
  }
  if (t == tlv::SignatureEd25519) {
    note = "OpenSSL Ed25519 over ndn-cxx extractSignedRanges (ndn-cxx 0.9 has no Ed25519 verifier)";
    EVP_PKEY* k = ed25519Key(signer.getPublicKey());
    if (k == nullptr) {
      note += "; signer key is not Ed25519";
      return false;
    }
    std::vector<uint8_t> region;
    for (const auto& r : data.extractSignedRanges())
      region.insert(region.end(), r.begin(), r.end());
    auto sig = data.getSignatureValue().value_bytes();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, k) == 1 &&
              EVP_DigestVerify(ctx, sig.data(), sig.size(), region.data(), region.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return ok;
  }
  note = "signature type " + sigTypeStr(t) + " not verifiable";
  return std::nullopt;
}

static int
cmdInspect(const std::vector<std::string>& files)
{
  for (const auto& f : files) {
    std::cout << "=== " << f << std::endl;
    std::optional<Certificate> cert;
    try {
      cert.emplace(loadData(f));
      report("PASS", "ndn-cxx decodes as v2 Certificate: " + cert->getName().toUri());
    }
    catch (const std::exception& e) {
      report("FAIL", std::string("ndn-cxx Certificate decode: ") + e.what());
      continue;
    }
    const Name& n = cert->getName();
    std::cout << "INFO: identity=" << cert->getIdentity() << " key=" << cert->getKeyName()
              << " key-id=" << cert->getKeyId().toUri() << " issuer-id=" << cert->getIssuerId().toUri()
              << std::endl;
    report(n.get(-1).isVersion() ? "PASS" : "FAIL",
           "last name component is a VersionNameComponent: " + n.get(-1).toUri());
    report(cert->getContentType() == tlv::ContentType_Key ? "PASS" : "FAIL", "ContentType is KEY (2)");
    try {
      auto vp = cert->getValidityPeriod();
      std::ostringstream os;
      os << vp;
      report(cert->isValid() ? "PASS" : "FAIL", "validity period " + os.str() + " covers now");
    }
    catch (const std::exception& e) {
      report("FAIL", std::string("ValidityPeriod: ") + e.what());
    }
    auto pk = describePublicKey(*cert);
    report(pk.empty() ? "FAIL" : "PASS", "public key parses: " + (pk.empty() ? "unrecognised" : pk));
    int t = sigType(*cert);
    std::cout << "INFO: signature type " << sigTypeStr(t) << std::endl;
    auto kl = cert->getKeyLocator();
    if (!kl || kl->getType() != tlv::Name) {
      report("FAIL", "KeyLocator is a Name");
      continue;
    }
    const Name& kln = kl->getName();
    auto form = keyLocatorForm(kln);
    if (form.empty())
      report("FAIL", "KeyLocator is neither a KEY nor a certificate name: " + kln.toUri());
    else if (form == "key")
      report("PASS", "KeyLocator is a KEY name: " + kln.toUri());
    else
      report(g_keyNameLocators ? "FAIL" : "PASS", "KeyLocator is a certificate name: " + kln.toUri());
    if (kln == cert->getKeyName() || kln == cert->getName()) {
      std::string note;
      auto ok = verifyWith(*cert, *cert, note);
      if (!ok)
        report("UNSUPPORTED", "self-signature check: " + note);
      else
        report(*ok ? "PASS" : "FAIL", "self-signature verifies (" + note + ")");
    }
  }
  return g_failures == 0 ? 0 : 1;
}

// Pick the newest currently-valid certificate whose name has `keyLocator` as a
// prefix (what a CanBePrefix fetch by key name should return).
static const Certificate*
pickCert(const Name& keyLocator, const std::vector<Certificate>& pool)
{
  const Certificate* best = nullptr;
  for (const auto& c : pool) {
    if (!keyLocator.isPrefixOf(c.getName()) || !c.isValid())
      continue;
    if (best == nullptr || c.getName().get(-1) > best->getName().get(-1))
      best = &c;
  }
  return best;
}

// Walk the chain by hand: resolve each KeyLocator to a certificate, check that
// the KeyLocator names the issuer's key (or, unless --key-name-locators, the
// issuer certificate itself) and verify each hop's signature.
static void
manualChain(const Data& target, const Certificate& anchor, const std::vector<Certificate>& certs)
{
  std::vector<Certificate> pool = certs;
  pool.push_back(anchor);
  const Data* cur = &target;
  for (int depth = 0; depth < 16; ++depth) {
    auto kl = cur->getKeyLocator();
    if (!kl || kl->getType() != tlv::Name) {
      report("FAIL", "chain: " + cur->getName().toUri() + " has no Name KeyLocator");
      return;
    }
    const Name& kln = kl->getName();
    const Certificate* signer = pickCert(kln, pool);
    if (signer == nullptr) {
      report("FAIL", "chain: no valid certificate under " + kln.toUri() + " (signer of " +
                       cur->getName().toUri() + ")");
      return;
    }
    if (kln == signer->getKeyName())
      report("PASS", "KeyLocator of " + cur->getName().toUri() + " is the issuer key name " + kln.toUri());
    else if (kln == signer->getName())
      report(g_keyNameLocators ? "FAIL" : "PASS",
             "KeyLocator of " + cur->getName().toUri() + " is the issuer certificate name " + kln.toUri());
    else
      report("FAIL", "KeyLocator " + kln.toUri() + " is neither the key nor the certificate name of " +
                       signer->getName().toUri());
    std::string note;
    auto ok = verifyWith(*cur, *signer, note);
    std::string hop = cur->getName().toUri() + " <- " + signer->getName().toUri();
    if (!ok) {
      report("UNSUPPORTED", "chain hop " + hop + ": " + note);
      return;
    }
    report(*ok ? "PASS" : "FAIL", "chain hop " + hop + " [" + sigTypeStr(sigType(*cur)) + ", " + note + "]");
    if (!*ok)
      return;
    if (signer->getName() == anchor.getName()) {
      report("PASS", "chain reaches trust anchor " + anchor.getName().toUri());
      return;
    }
    if (signer == cur) {
      report("FAIL", "chain ends at self-signed " + signer->getName().toUri() + " which is not the anchor");
      return;
    }
    cur = signer;
  }
  report("FAIL", "chain: depth limit exceeded");
}

// validator.conf for the ndn-cxx Validator. "keylocator-v2-name" admits any
// packet whose KeyLocator is a key or certificate name (the namespace layout
// /<ns>/CA certifying /<ns>/<role>/... is governed by the namespace's trust
// schema, not by name hierarchy); "hierarchical" is NFD's stock rule, which
// requires the signer identity to be a prefix of the signed name.
static std::string
policyText(const std::string& checkerKind, const Certificate& anchor)
{
  std::ostringstream os;
  os << "rule\n{\n  id \"" << checkerKind << "\"\n  for data\n"
     << "  filter\n  {\n    type name\n    name /\n    relation is-prefix-of\n  }\n";
  for (const char* st : {"ecdsa-sha256", "rsa-sha256"}) {
    os << "  checker\n  {\n";
    if (checkerKind == "hierarchical") {
      os << "    type hierarchical\n    sig-type " << st << "\n";
    }
    else {
      os << "    type customized\n    sig-type " << st << "\n"
         << "    key-locator\n    {\n      type name\n      regex ^<>*<KEY><>{1,3}$\n    }\n";
    }
    os << "  }\n";
  }
  os << "}\n";
  std::ostringstream b64;
  io::save(anchor, b64, io::BASE64);
  std::string s = b64.str();
  s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
  os << "trust-anchor\n{\n  type base64\n  base64-string \"" << s << "\"\n}\n";
  return os.str();
}

// Run the ndn-cxx Validator with an offline fetcher over the given certificates.
// `strict`: a refusal is a FAIL (else a NOTE). With Ed25519 anywhere in the
// chain a refusal is UNSUPPORTED: ndn-cxx 0.9 has no Ed25519 verifier.
static void
ndncxxValidator(const std::string& kind, const Data& target, const Certificate& anchor,
                const std::vector<Certificate>& certs, bool hasEd25519, bool strict)
{
  auto policy = std::make_unique<security::ValidationPolicyConfig>();
  auto* policyPtr = policy.get();
  security::Validator validator(std::move(policy), std::make_unique<security::CertificateFetcherOffline>());
  policyPtr->load(policyText(kind, anchor), "ndncxx-interop-" + kind + ".conf");
  for (auto c : certs)
    validator.cacheUnverifiedCert(std::move(c));

  std::optional<std::string> result;
  validator.validate(target,
    [&] (const Data&) { result = ""; },
    [&] (const Data&, const security::ValidationError& err) {
      std::ostringstream os;
      os << err;
      result = os.str();
    });
  std::string label = "ndn-cxx Validator (" + kind + " policy, offline fetcher)";
  if (!result)
    report("FAIL", label + ": validation did not complete");
  else if (result->empty())
    report("PASS", label + ": " + target.getName().toUri());
  else if (hasEd25519)
    report("UNSUPPORTED", label + ": Ed25519 in chain, ndn-cxx 0.9 cannot verify it (" + *result + ")");
  else
    report(strict ? "FAIL" : "NOTE", label + ": " + *result);
}

static int
cmdValidate(const std::string& anchorFile, const std::vector<std::string>& certFiles,
            const std::string& targetFile)
{
  std::optional<Certificate> anchor;
  std::vector<Certificate> certs;
  std::optional<Data> target;
  try {
    anchor.emplace(loadData(anchorFile));
    for (const auto& f : certFiles)
      certs.emplace_back(loadData(f));
    target.emplace(loadData(targetFile));
  }
  catch (const std::exception& e) {
    report("FAIL", std::string("decode inputs: ") + e.what());
    return 1;
  }
  std::cout << "INFO: target " << target->getName() << " (" << sigTypeStr(sigType(*target))
            << ", KeyLocator " << (target->getKeyLocator() ? target->getKeyLocator()->getName().toUri() : "-")
            << ")" << std::endl;
  std::cout << "INFO: anchor " << anchor->getName() << std::endl;

  bool hasEd25519 = sigType(*target) == tlv::SignatureEd25519 || sigType(*anchor) == tlv::SignatureEd25519;
  for (const auto& c : certs)
    hasEd25519 = hasEd25519 || sigType(c) == tlv::SignatureEd25519;

  manualChain(*target, *anchor, certs);
  ndncxxValidator("keylocator-v2-name", *target, *anchor, certs, hasEd25519, true);
  // Informational: a CA under /<ns>/CA issuing /<ns>/<role>/<dev> is not
  // hierarchical by design, so this rule's refusal never counts as a failure.
  ndncxxValidator("hierarchical", *target, *anchor, certs, hasEd25519, false);
  return g_failures == 0 ? 0 : 1;
}

static int
usage()
{
  std::cerr << "usage:\n"
            << "  ndncxx-interop [--key-name-locators] inspect FILE...\n"
            << "  ndncxx-interop [--key-name-locators] validate --anchor FILE [--cert FILE]... TARGET\n";
  return 2;
}

int
main(int argc, char** argv)
{
  std::vector<std::string> args(argv + 1, argv + argc);
  if (!args.empty() && args.front() == "--key-name-locators") {
    g_keyNameLocators = true;
    args.erase(args.begin());
  }
  if (args.empty())
    return usage();
  std::string cmd = args.front();
  args.erase(args.begin());
  try {
    if (cmd == "inspect") {
      if (args.empty())
        return usage();
      return cmdInspect(args);
    }
    if (cmd == "validate") {
      std::string anchor, target;
      std::vector<std::string> certs;
      for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--anchor" && i + 1 < args.size())
          anchor = args[++i];
        else if (args[i] == "--cert" && i + 1 < args.size())
          certs.push_back(args[++i]);
        else if (target.empty())
          target = args[i];
        else
          return usage();
      }
      if (anchor.empty() || target.empty())
        return usage();
      return cmdValidate(anchor, certs, target);
    }
  }
  catch (const std::exception& e) {
    report("FAIL", std::string("exception: ") + e.what());
    return 1;
  }
  return usage();
}
