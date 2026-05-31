// Deterministic PSync FullProducer fixture for ndn-rs G.03 interop.
//
// Upstream examples use random publish timers, which makes the witness slow
// and occasionally unlucky. This fixture keeps the same PSync FullProducer
// protocol path but publishes a fixed number of updates at fixed intervals.

#include <PSync/full-producer.hpp>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/scheduler.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace ndn::time_literals;

class DeterministicProducer
{
public:
  DeterministicProducer(const ndn::Name& syncPrefix, const std::string& userPrefix,
                        size_t updateCount, uint64_t firstDelayMs, uint64_t intervalMs)
    : m_updateCount(updateCount)
    , m_intervalMs(intervalMs)
    , m_producer(m_face, m_keyChain, syncPrefix, [] {
        psync::FullProducer::Options opts;
        opts.syncInterestLifetime = 1000_ms;
        opts.syncDataFreshness = 1000_ms;
        return opts;
      }())
  {
    for (size_t i = 0; i < m_updateCount; ++i) {
      ndn::Name prefix(userPrefix + "-" + std::to_string(i));
      m_prefixes.push_back(prefix);
      m_producer.addUserNode(prefix);
    }

    m_scheduler.schedule(ndn::time::milliseconds(firstDelayMs), [this] {
      publishNext();
    });
  }

  void run()
  {
    m_face.processEvents();
  }

private:
  void publishNext()
  {
    if (m_next >= m_updateCount) {
      return;
    }

    const auto& prefix = m_prefixes[m_next++];
    m_producer.publishName(prefix);
    auto seq = m_producer.getSeqNo(prefix).value_or(0);
    std::cout << "PUBLISH " << prefix << "/" << seq << std::endl;

    if (m_next < m_updateCount) {
      m_scheduler.schedule(ndn::time::milliseconds(m_intervalMs), [this] {
        publishNext();
      });
    }
  }

private:
  ndn::Face m_face;
  ndn::KeyChain m_keyChain;
  ndn::Scheduler m_scheduler{m_face.getIoContext()};
  size_t m_updateCount = 0;
  size_t m_next = 0;
  uint64_t m_intervalMs = 0;
  std::vector<ndn::Name> m_prefixes;
  psync::FullProducer m_producer;
};

int main(int argc, char* argv[])
{
  if (argc != 6) {
    std::cerr << "Usage: " << argv[0]
              << " <sync-prefix> <user-prefix> <update-count> <first-delay-ms> <interval-ms>\n";
    return 1;
  }

  try {
    DeterministicProducer producer(argv[1], argv[2],
                                   static_cast<size_t>(std::stoul(argv[3])),
                                   std::stoull(argv[4]),
                                   std::stoull(argv[5]));
    producer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR " << e.what() << std::endl;
    return 1;
  }
}
