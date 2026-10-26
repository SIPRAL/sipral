/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * register-and-hold.c again, through the C++ layer (bindings/cpp): no socket,
 * no TLS, no resolver and no handle freed by hand. scripts/lab.sh's `network`
 * step runs both against Asterisk with the same name server.
 *
 *   register-and-hold-cpp <sip-domain> <ca-file> <user> <password> <extension>
 *
 * Prints the same lines as the C program, and exits 0 when it was registered,
 * heard the far end, held, resumed, heard it again and hung up; 2 otherwise.
 */
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "sipral.hpp"

namespace {

struct Line {
    bool registered = false;
    bool unregistered = false;
    bool media_started = false;
    int sessions_changed = 0;
    bool ended = false;
    sipral::Handle call = SIPRAL_HANDLE_NONE;
};

const char *record_name(sipral_dns_record_type_t record)
{
    switch (record) {
    case SIPRAL_DNS_RECORD_TYPE_NAPTR: return "NAPTR";
    case SIPRAL_DNS_RECORD_TYPE_SRV: return "SRV";
    case SIPRAL_DNS_RECORD_TYPE_A: return "A";
    default: return "AAAA";
    }
}

void on_event(Line &line, const sipral::Event &event)
{
    const sipral_event_t &raw = event.raw();
    switch (event.kind()) {
    case SIPRAL_EVENT_KIND_LOOKUP_WANTED:
        std::printf("lookup %s %.*s\n", record_name(raw.payload.locate.record), static_cast<int>(raw.payload.locate.name_len),
                    raw.payload.locate.name);
        break;
    case SIPRAL_EVENT_KIND_LOCATED:
        std::printf("located %.*s\n", static_cast<int>(raw.payload.locate.targets_len), raw.payload.locate.targets);
        break;
    case SIPRAL_EVENT_KIND_TRANSPORT_FAILED:
        std::printf("transport failed: %.*s\n", static_cast<int>(raw.payload.transport_failed.detail_len),
                    raw.payload.transport_failed.detail != nullptr ? raw.payload.transport_failed.detail : "");
        break;
    case SIPRAL_EVENT_KIND_REGISTRATION_CHANGED:
        if (raw.payload.registration.state == SIPRAL_REGISTRATION_STATE_REGISTERED && !line.registered) {
            std::printf("registered\n");
            line.registered = true;
        } else if (raw.payload.registration.state == SIPRAL_REGISTRATION_STATE_UNREGISTERED && line.registered) {
            std::printf("unregistered\n");
            line.unregistered = true;
        }
        break;
    case SIPRAL_EVENT_KIND_MEDIA_STARTED:
        line.media_started = line.media_started || event.call() == line.call;
        break;
    case SIPRAL_EVENT_KIND_SESSION_CHANGED:
        if (event.call() == line.call) {
            ++line.sessions_changed;
        }
        break;
    case SIPRAL_EVENT_KIND_CALL_ENDED:
        if (event.call() == line.call) {
            std::printf("ended\n");
            line.ended = true;
        }
        break;
    default:
        break;
    }
}

/** Turn the component's loop until `done` says so, or `limit_ms` passes. */
template <typename Done> bool run_until(sipral::Stack &stack, Done done, std::uint64_t limit_ms)
{
    std::uint64_t deadline = sipral::now_ms() + limit_ms;
    while (!done() && sipral::now_ms() < deadline) {
        stack.run(20);
    }
    return done();
}

/** Carry the call's audio for `ms`; how many frames came from the far end's packets. */
int talk(sipral::Stack &stack, sipral::Handle media, std::size_t frame_samples, std::uint64_t ms)
{
    std::vector<std::int16_t> silence(frame_samples);
    std::vector<std::int16_t> heard(frame_samples);
    int from_far_end = 0;
    std::uint64_t until = sipral::now_ms() + ms;
    std::uint64_t next_frame = sipral::now_ms();
    while (sipral::now_ms() < until) {
        stack.run(5);
        if (sipral::now_ms() < next_frame) {
            continue;
        }
        next_frame += 20;
        stack.capture(media, silence.data(), silence.size());
        from_far_end += sipral::playback(media, heard.data(), heard.size()) ? 1 : 0;
    }
    return from_far_end;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 6) {
        std::fprintf(stderr, "usage: %s <sip-domain> <ca-file> <user> <password> <extension>\n", argv[0]);
        return 64;
    }
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::string domain = argv[1];
    std::string user = argv[3];
    std::string password = argv[4];
    if (!sipral::has_network()) {
        std::printf("this library has no networking component\n");
        return 2;
    }
    std::ifstream file(argv[2]);
    std::string authority((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (authority.empty()) {
        std::fprintf(stderr, "no authority in %s\n", argv[2]);
        return 1;
    }
    sipral::NetworkOptions net;
    net.trust = SIPRAL_NETWORK_TRUST_ONLY_AUTHORITY;
    net.authority_pem = authority;

    Line line;
    bool ok = false;
    try {
        std::string server_uri = "sips:" + domain;
        std::string located = sipral::locate(net, server_uri, SIPRAL_TRANSPORT_TLS);
        std::printf("found %s\n", located.c_str());
        std::string local = sipral::advertised_address("0.0.0.0:0", located.substr(0, located.find(',')));
        std::string host = local.substr(0, local.rfind(':'));

        sipral::StackOptions options;
        options.bind_address = local;
        options.on_event = [&line](const sipral::Event &event) { on_event(line, event); };
        sipral::Stack stack(std::move(options));
        stack.start_network(net);

        sipral::AccountOptions account_options;
        account_options.aor = "sip:" + user + "@" + domain;
        account_options.registrar = "sip:" + domain;
        account_options.contact = "sip:" + user + "@" + host + ";transport=tls";
        account_options.server_uri = server_uri;
        account_options.server_naptr = true;
        account_options.stream_protocol = SIPRAL_TRANSPORT_TLS;
        account_options.srtp = SIPRAL_SRTP_NOT_OFFERED;
        account_options.auth_user = user;
        account_options.auth_password = password;
        sipral::Account account = stack.add_account(account_options);
        account.start_registration();
        ok = run_until(stack, [&] { return line.registered; }, 20000);

        if (ok) {
            std::string media_at = stack.open_media();
            sipral::Call call = account.place_call("sip:" + std::string(argv[5]) + "@" + domain, media_at);
            line.call = call.handle();
            ok = run_until(stack, [&] { return line.media_started; }, 20000);
            if (ok) {
                sipral::Handle media = stack.attach_media(media_at, call);
                std::size_t frame = sipral::frame_samples(media);
                int heard = talk(stack, media, frame, 4000);
                std::printf("heard %d frames from the far end\n", heard);
                ok = heard >= 25;
                if (ok) {
                    int before = line.sessions_changed;
                    call.hold();
                    ok = run_until(stack, [&] { return line.sessions_changed > before; }, 10000);
                    if (ok) {
                        std::printf("held\n");
                        talk(stack, media, frame, 2000);
                    }
                }
                if (ok) {
                    int before = line.sessions_changed;
                    call.resume();
                    ok = run_until(stack, [&] { return line.sessions_changed > before; }, 10000);
                    if (ok) {
                        std::printf("resumed\n");
                        int again = talk(stack, media, frame, 4000);
                        std::printf("heard %d frames from the far end after resuming\n", again);
                        ok = again >= 25;
                    }
                }
            }
            if (!line.ended) {
                call.hangup();
                run_until(stack, [&] { return line.ended; }, 10000);
            }
        }
        if (line.registered) {
            account.stop_registration();
            run_until(stack, [&] { return line.unregistered; }, 10000);
        }
    } catch (const sipral::Error &error) {
        std::printf("failed: %s\n", error.what());
        return 2;
    }
    return ok && line.ended ? 0 : 2;
}
