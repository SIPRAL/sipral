/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * The C++ layer, compiled the way an integrator compiles it (C++17, warnings
 * fatal) and run against the shared library: a refused stack is an Error
 * with its status, an account goes with its object, a call's INVITE passes a
 * message hook that adds a header, a hook that throws keeps the message
 * and has its exception come out of the next poll(), and an account that is a
 * WebRTC line offers DTLS-SRTP on UDP/TLS/RTP/SAVPF.
 *
 * Exits 0 when every check holds; prints each one that did not.
 */
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "include/sipral.hpp"

namespace {

int failures = 0;

void expect(bool holds, const char *what)
{
    if (!holds) {
        std::fprintf(stderr, "smoke.cpp: %s\n", what);
        ++failures;
    }
}

/** Every message the stack wants written, drained. */
std::vector<std::string> sent(sipral::Handle stack)
{
    std::vector<std::string> out;
    std::vector<std::uint8_t> data(65536);
    std::vector<char> destination(SIPRAL_ADDRESS_BYTES);
    for (;;) {
        sipral_transmit_t transmit{};
        transmit.size = sizeof transmit;
        transmit.data = data.data();
        transmit.capacity = data.size();
        transmit.destination = destination.data();
        transmit.destination_capacity = destination.size();
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK || transmit.len == 0) {
            return out;
        }
        out.emplace_back(reinterpret_cast<const char *>(data.data()), transmit.len);
    }
}

sipral::AccountOptions alice()
{
    sipral::AccountOptions options;
    options.aor = "sip:alice@127.0.0.1";
    options.registrar = "sip:127.0.0.1:5999";
    options.contact = "sip:alice@127.0.0.1";
    options.registrar_address = "127.0.0.1:5999";
    return options;
}

std::string with_header(std::string_view message, std::string_view line)
{
    std::string out(message);
    auto end = out.find("\r\n\r\n");
    if (end != std::string::npos) {
        out.insert(end + 2, std::string(line) + "\r\n");
    }
    return out;
}

} // namespace

int main()
{
    sipral::StackOptions refused;
    refused.bind_address = "not an address";
    try {
        sipral::Stack stack(std::move(refused));
        expect(false, "a stack bound to no address was made");
    } catch (const sipral::Error &error) {
        expect(error.status() == SIPRAL_STATUS_INVALID_ARGUMENT, "a bad address is not INVALID_ARGUMENT");
        expect(std::string(error.what()).find("sipral_stack_create") == 0, "the error does not name the call");
    }

    sipral::StackOptions options;
    options.bind_address = "127.0.0.1:5998";
    sipral::Stack stack(std::move(options));
    expect(stack.handle() != SIPRAL_HANDLE_NONE, "the stack has no handle");

    sipral::Handle gone = SIPRAL_HANDLE_NONE;
    {
        sipral::Account account = stack.add_account(alice());
        gone = account.handle();
        sipral::Account moved = std::move(account);
        expect(account.handle() == SIPRAL_HANDLE_NONE, "a moved-from account still holds its handle");
        expect(moved.handle() == gone, "the moved-to account lost the handle");
    }
    expect(sipral_account_register(stack.handle(), gone, sipral::now_ms()) != SIPRAL_STATUS_OK,
           "an account outlived its object");

    std::vector<std::string> seen;
    stack.set_message_hook([&seen](const sipral::Hooked &message) {
        seen.emplace_back(message.message);
        if (message.outgoing && message.message.rfind("INVITE ", 0) == 0) {
            return sipral::Verdict::replace(with_header(message.message, "X-Tenant: blue"));
        }
        return sipral::Verdict::keep();
    });
    sipral::Account account = stack.add_account(alice());
    sipral::Call call = account.place_call("sip:bob@127.0.0.1:5999", "127.0.0.1:40000");
    expect(call.handle() != SIPRAL_HANDLE_NONE, "the call has no handle");
    bool tagged = false;
    for (const auto &message : sent(stack.handle())) {
        if (message.rfind("INVITE ", 0) == 0) {
            tagged = message.find("\r\nX-Tenant: blue\r\n") != std::string::npos;
        }
    }
    expect(tagged, "the INVITE did not carry the header the hook added");
    expect(!seen.empty(), "the hook saw nothing");

    stack.set_message_hook([](const sipral::Hooked &) -> sipral::Verdict {
        throw std::runtime_error("a mistake in the application's hook");
    });
    sipral::Call second = account.place_call("sip:carol@127.0.0.1:5999", "127.0.0.1:40002");
    expect(second.handle() != call.handle(), "two calls share a handle");
    bool kept = false;
    for (const auto &message : sent(stack.handle())) {
        kept = kept || (message.rfind("INVITE sip:carol@", 0) == 0 &&
                        message.find("X-Tenant") == std::string::npos);
    }
    expect(kept, "a hook that threw stopped the INVITE, or changed it");
    try {
        stack.poll();
        expect(false, "the hook's exception never came out of poll()");
    } catch (const std::runtime_error &error) {
        expect(std::string(error.what()) == "a mistake in the application's hook",
               "poll() threw something other than the hook's exception");
    }
    stack.set_message_hook({});
    stack.poll();

    sipral::AccountOptions line = alice();
    line.aor = "sip:dave@127.0.0.1";
    line.webrtc = true;
    sipral::Account webrtc = stack.add_account(line);
    // the line offers ICE, which keeps loopback out of its candidates (RFC 8445
    // §5.1.1.1): the media address is a documentation one (RFC 5737), and
    // nothing here is sent anywhere
    webrtc.place_call("sip:erin@127.0.0.1:5999", "192.0.2.10:40004");
    bool offered = false;
    for (const auto &message : sent(stack.handle())) {
        offered = offered || (message.rfind("INVITE sip:erin@", 0) == 0 &&
                              message.find("UDP/TLS/RTP/SAVPF") != std::string::npos &&
                              message.find("a=fingerprint:") != std::string::npos);
    }
    expect(offered, "a WebRTC line's INVITE did not offer DTLS-SRTP on UDP/TLS/RTP/SAVPF");


    expect(sipral::advertised_address("0.0.0.0:0", "127.0.0.1:5999").rfind("127.0.0.1:", 0) == 0,
           "the way toward loopback is not loopback");
    if (!sipral::has_network()) {
        try {
            stack.start_network(sipral::NetworkOptions{});
            expect(false, "a library without the networking component started it");
        } catch (const sipral::Error &error) {
            expect(error.status() == SIPRAL_STATUS_NOT_SUPPORTED, "no networking component is not NOT_SUPPORTED");
        }
    }

    if (failures == 0) {
        std::printf("smoke.cpp: every check held\n");
    }
    return failures == 0 ? 0 : 1;
}
