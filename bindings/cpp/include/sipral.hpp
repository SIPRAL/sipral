/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * Sipral from C++: the stack, its accounts and calls, its events and its
 * message hook as classes over the C ABI in sipral.h, header only, C++17.
 *
 * What it adds to the C ABI is the bookkeeping a C program writes by hand:
 * a stack is destroyed with its object, an account removed with its, the
 * networking component stopped before its stack goes; a failed call into the
 * library is a sipral::Error carrying the status and the library's own
 * sentence; an event or hook handler is a std::function, and an exception it
 * throws never crosses into the library but comes out of the call that ran it.
 * Everything else in sipral.h stays reachable through each object's handle().
 * docs/27-cpp.md has the whole of it.
 */
#ifndef SIPRAL_HPP
#define SIPRAL_HPP

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "sipral.h"

namespace sipral {

using Handle = sipral_handle_t;

/** A call into the library that did not succeed: its status, and the library's sentence about it. */
class Error : public std::runtime_error {
public:
    Error(sipral_status_t status, const std::string &what) : std::runtime_error(what), status_(status) {}

    /** The status the library answered. */
    sipral_status_t status() const noexcept { return status_; }

private:
    sipral_status_t status_;
};

namespace detail {

/** The library's last error on this thread, or the status's name when it kept none. */
inline std::string last_error(sipral_status_t status)
{
    std::size_t needed = 0;
    std::string text(256, '\0');
    if (sipral_last_error_message(text.data(), text.size(), &needed) == SIPRAL_STATUS_BUFFER_TOO_SMALL) {
        text.assign(needed, '\0');
        sipral_last_error_message(text.data(), text.size(), &needed);
    }
    text.resize(needed > 0 ? needed - 1 : 0);
    if (text.empty()) {
        const char *name = sipral_status_name(static_cast<std::int32_t>(status));
        text = name != nullptr ? name : "unknown status";
    }
    return text;
}

inline void check(sipral_status_t status, const char *call)
{
    if (status != SIPRAL_STATUS_OK) {
        throw Error(status, std::string(call) + ": " + last_error(status));
    }
}

/** Milliseconds on a clock that never goes back, as every `now_ms` in the C ABI wants. */
inline std::uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

/** 32 bytes from the platform's source of randomness, for a stack's seeds. */
inline std::array<std::uint8_t, 32> entropy()
{
    std::random_device device;
    std::array<std::uint8_t, 32> out{};
    for (auto &byte : out) {
        byte = static_cast<std::uint8_t>(device());
    }
    return out;
}

} // namespace detail

using detail::now_ms;

/** One event, valid inside the handler it is given to. */
class Event {
public:
    explicit Event(const sipral_event_t &raw) : raw_(raw) {}

    sipral_event_kind_t kind() const noexcept { return raw_.kind; }
    /** The account it is about, or SIPRAL_HANDLE_NONE. */
    Handle account() const noexcept { return raw_.account; }
    /** The call it is about, or SIPRAL_HANDLE_NONE. */
    Handle call() const noexcept { return raw_.call; }
    /** The SIP message behind it, when there was one. */
    std::string_view message() const noexcept
    {
        return raw_.message != nullptr
                   ? std::string_view(reinterpret_cast<const char *>(raw_.message), raw_.message_len)
                   : std::string_view();
    }
    /** The whole C event, payload included. */
    const sipral_event_t &raw() const noexcept { return raw_; }

private:
    const sipral_event_t &raw_;
};

/** One SIP message as a message hook sees it, valid inside the hook. */
struct Hooked {
    /** True on its way out, false just arrived. */
    bool outgoing;
    /** What it travels over; zero for one the ABI has no name for. */
    sipral_transport_t transport;
    /** The far end, as `host:port`. */
    std::string_view remote;
    /** The message, from its start line to the end of its body. */
    std::string_view message;
};

/** What a message hook decided. */
class Verdict {
public:
    /** The message goes on as it is. */
    static Verdict keep() { return Verdict(SIPRAL_HOOK_KEEP, {}); }
    /** The message goes no further. */
    static Verdict drop() { return Verdict(SIPRAL_HOOK_DROP, {}); }
    /** The message goes on as `message` instead; its Content-Length must match its body. */
    static Verdict replace(std::string message) { return Verdict(SIPRAL_HOOK_REPLACE, std::move(message)); }

    std::uint32_t answer() const noexcept { return answer_; }
    const std::string &replacement() const noexcept { return replacement_; }

private:
    Verdict(std::uint32_t answer, std::string replacement) : answer_(answer), replacement_(std::move(replacement)) {}

    std::uint32_t answer_;
    std::string replacement_;
};

/** How the networking component trusts a server and finds names (sipral_network_config_t). */
struct NetworkOptions {
    sipral_network_trust_t trust = SIPRAL_NETWORK_TRUST_PLATFORM;
    /** PEM authorities, for SIPRAL_NETWORK_TRUST_PLATFORM_AND_AUTHORITY and _ONLY_AUTHORITY. */
    std::string authority_pem;
    /** A certificate's SHA-256, for SIPRAL_NETWORK_TRUST_PINNED. */
    std::string pin_sha256;
    /** A client certificate and its key, both PEM, for a server that asks for one. */
    std::string client_certificate_pem;
    std::string client_key_pem;
    /** Name servers to ask instead of the system's, comma-separated `host:port`. */
    std::string name_servers;
};

namespace detail {

/** `options` as the C struct, borrowing its strings. */
inline sipral_network_config_t network_config(const NetworkOptions &options)
{
    auto text = [](const std::string &value) { return value.empty() ? nullptr : value.data(); };
    sipral_network_config_t config{};
    config.size = sizeof config;
    config.trust = options.trust;
    config.authority_pem = text(options.authority_pem);
    config.authority_pem_len = options.authority_pem.size();
    config.pin_sha256 = text(options.pin_sha256);
    config.pin_sha256_len = options.pin_sha256.size();
    config.client_certificate_pem = text(options.client_certificate_pem);
    config.client_certificate_pem_len = options.client_certificate_pem.size();
    config.client_key_pem = text(options.client_key_pem);
    config.client_key_pem_len = options.client_key_pem.size();
    config.name_servers = text(options.name_servers);
    config.name_servers_len = options.name_servers.size();
    return config;
}

/** The text a `(buffer, capacity, out_needed)` entry point writes, at whatever length it needs. */
template <typename Write> std::string text_from(Write write, const char *call)
{
    std::string out(SIPRAL_ADDRESS_BYTES, '\0');
    std::size_t needed = 0;
    sipral_status_t status = write(out.data(), out.size(), &needed);
    if (status == SIPRAL_STATUS_BUFFER_TOO_SMALL) {
        out.assign(needed, '\0');
        status = write(out.data(), out.size(), &needed);
    }
    check(status, call);
    out.resize(needed > 0 ? needed - 1 : 0);
    return out;
}

} // namespace detail

/** Whether this library carries the networking component (sipral-ffi's `network` feature). */
inline bool has_network()
{
    sipral_capabilities_t capabilities{};
    capabilities.size = sizeof capabilities;
    return sipral_capabilities(&capabilities) == SIPRAL_STATUS_OK &&
           (capabilities.features & SIPRAL_FEATURE_NETWORK) != 0;
}

/** Where RFC 3263 finds `server_uri` over `protocol`, as `host:port` targets, comma-separated. */
inline std::string locate(const NetworkOptions &options, std::string_view server_uri, sipral_transport_t protocol)
{
    sipral_network_config_t config = detail::network_config(options);
    return detail::text_from(
        [&](char *buffer, std::size_t capacity, std::size_t *needed) {
            return sipral_network_locate(&config, server_uri.data(), server_uri.size(), protocol, buffer, capacity,
                                         needed);
        },
        "sipral_network_locate");
}

/** The address a socket bound at `bound` is reached at by `peer`: the interface toward it. */
inline std::string advertised_address(std::string_view bound, std::string_view peer)
{
    return detail::text_from(
        [&](char *buffer, std::size_t capacity, std::size_t *needed) {
            return sipral_advertised_address(bound.data(), bound.size(), peer.data(), peer.size(), buffer, capacity,
                                             needed);
        },
        "sipral_advertised_address");
}

/** How many samples one frame of a call's media holds. */
inline std::size_t frame_samples(Handle media)
{
    sipral_media_info_t info{};
    info.size = sizeof info;
    detail::check(sipral_media_info(media, &info), "sipral_media_info");
    return info.frame_samples;
}

/** The next frame to play, into `samples`; true when it came from the far end's packets. */
inline bool playback(Handle media, std::int16_t *samples, std::size_t count)
{
    std::size_t written = 0;
    sipral_playback_t source{};
    detail::check(sipral_media_playback(media, samples, count, &written, &source), "sipral_media_playback");
    return source == SIPRAL_PLAYBACK_PACKET;
}

/** What a stack is made with (sipral_stack_config_t, the members most programs set). */
struct StackOptions {
    /** Where its main transport listens, `host:port`. */
    std::string bind_address = "0.0.0.0:0";
    sipral_transport_t transport = SIPRAL_TRANSPORT_UDP;
    /** Called for every event, on the thread inside poll() or run(). */
    std::function<void(const Event &)> on_event;
};

/** What an account is made with (sipral_account_config_t, the members most programs set). */
struct AccountOptions {
    std::string aor;
    std::string registrar;
    std::string contact;
    /** Where to send, `host:port`, when it is known; otherwise server_uri. */
    std::string registrar_address;
    /** Where to send, when RFC 3263 should find it: `sip:` or `sips:` and a domain. */
    std::string server_uri;
    bool server_naptr = false;
    /** The transport to open toward the server; zero leaves the stack's own. */
    sipral_transport_t stream_protocol = static_cast<sipral_transport_t>(0);
    sipral_srtp_t srtp = static_cast<sipral_srtp_t>(0);
    std::string auth_user;
    std::string auth_password;
};

class Stack;

/** A call this program placed or was offered. Ending it is hangup(); the library forgets it after
 * SIPRAL_EVENT_KIND_CALL_ENDED, and the object holds nothing to free. */
class Call {
public:
    Call(Handle stack, Handle call) : stack_(stack), call_(call) {}

    Handle handle() const noexcept { return call_; }

    void answer() { detail::check(sipral_call_answer(stack_, call_, nullptr, 0, now_ms()), "sipral_call_answer"); }
    void reject(std::uint32_t code = 486)
    {
        detail::check(sipral_call_reject(stack_, call_, code, now_ms()), "sipral_call_reject");
    }
    void hangup() { detail::check(sipral_call_hangup(stack_, call_, now_ms()), "sipral_call_hangup"); }
    void hold() { detail::check(sipral_call_hold(stack_, call_, now_ms()), "sipral_call_hold"); }
    void resume() { detail::check(sipral_call_resume(stack_, call_, now_ms()), "sipral_call_resume"); }
    void send_dtmf(std::string_view digits, sipral_dtmf_t via = SIPRAL_DTMF_RTP, std::uint32_t duration_ms = 100)
    {
        detail::check(sipral_call_send_dtmf(stack_, call_, digits.data(), digits.size(), via, duration_ms, now_ms()),
                      "sipral_call_send_dtmf");
    }
    /** The call's media handle, for the sipral_media_* functions, once media has started. */
    Handle media() const
    {
        Handle out = SIPRAL_HANDLE_NONE;
        detail::check(sipral_call_media(stack_, call_, &out), "sipral_call_media");
        return out;
    }

private:
    Handle stack_;
    Handle call_;
};

/** An account on a stack, removed from it when the object goes. */
class Account {
public:
    Account(const Account &) = delete;
    Account &operator=(const Account &) = delete;
    Account(Account &&other) noexcept
        : stack_(other.stack_), account_(std::exchange(other.account_, SIPRAL_HANDLE_NONE)) {}
    Account &operator=(Account &&other) noexcept
    {
        if (this != &other) {
            release();
            stack_ = other.stack_;
            account_ = std::exchange(other.account_, SIPRAL_HANDLE_NONE);
        }
        return *this;
    }
    ~Account() { release(); }

    Handle handle() const noexcept { return account_; }

    /** Send the REGISTER; SIPRAL_EVENT_KIND_REGISTRATION_CHANGED says how it went. */
    void start_registration()
    {
        detail::check(sipral_account_register(stack_, account_, now_ms()), "sipral_account_register");
    }
    /** Take the binding away at the registrar. */
    void stop_registration()
    {
        detail::check(sipral_account_unregister(stack_, account_, now_ms()), "sipral_account_unregister");
    }
    /** Place a call to `target`, its media described by this stack at `media_address` (`host:port`; with
     * the networking component, what Stack::open_media() gave). */
    Call place_call(std::string_view target, std::string_view media_address)
    {
        sipral_call_config_t config{};
        config.size = sizeof config;
        config.target = target.data();
        config.target_len = target.size();
        config.media_address = media_address.data();
        config.media_address_len = media_address.size();
        Handle call = SIPRAL_HANDLE_NONE;
        detail::check(sipral_call_place(stack_, account_, &config, &call, now_ms()), "sipral_call_place");
        return Call(stack_, call);
    }

private:
    friend class Stack;
    Account(Handle stack, Handle account) : stack_(stack), account_(account) {}

    void release() noexcept
    {
        if (account_ != SIPRAL_HANDLE_NONE) {
            sipral_account_remove(stack_, account_);
            account_ = SIPRAL_HANDLE_NONE;
        }
    }

    Handle stack_;
    Handle account_;
};

/** A stack, destroyed with the object; its networking component, when started, stopped first. */
class Stack {
public:
    explicit Stack(StackOptions options) : state_(std::make_unique<State>())
    {
        state_->on_event = std::move(options.on_event);
        state_->bind_address = std::move(options.bind_address);
        auto seed = detail::entropy();
        auto media_seed = detail::entropy();
        sipral_stack_config_t config{};
        config.size = sizeof config;
        config.event_callback = &Stack::deliver;
        config.event_user_data = state_.get();
        config.transport = options.transport;
        config.bind_address = state_->bind_address.data();
        config.bind_address_len = state_->bind_address.size();
        config.entropy = seed.data();
        config.entropy_len = seed.size();
        config.media_seed = media_seed.data();
        config.media_seed_len = media_seed.size();
        detail::check(sipral_stack_create(&config, &state_->stack), "sipral_stack_create");
    }
    Stack(const Stack &) = delete;
    Stack &operator=(const Stack &) = delete;
    Stack(Stack &&) noexcept = default;
    Stack &operator=(Stack &&other) noexcept
    {
        if (this != &other) {
            release();
            state_ = std::move(other.state_);
        }
        return *this;
    }
    ~Stack() { release(); }

    /** The C handle; SIPRAL_HANDLE_NONE once the object was moved from. */
    Handle handle() const noexcept { return state_ ? state_->stack : SIPRAL_HANDLE_NONE; }

    /** Let the stack do what is due and deliver its events. */
    void poll()
    {
        sipral_poll_result_t result{};
        result.size = sizeof result;
        state_->settle(sipral_stack_poll(state_->stack, now_ms(), &result), "sipral_stack_poll");
    }

    /** Hand this stack's sockets, TLS and lookups to the library (sipral_network_*). */
    void start_network(const NetworkOptions &options)
    {
        sipral_network_config_t config = detail::network_config(options);
        detail::check(sipral_network_start(state_->stack, &config, now_ms()), "sipral_network_start");
        state_->network = true;
    }

    /** With the networking component: a socket for a call's media, its address to place the call with. */
    std::string open_media()
    {
        return detail::text_from(
            [&](char *buffer, std::size_t capacity, std::size_t *needed) {
                return sipral_network_media_open(state_->stack, buffer, capacity, needed);
            },
            "sipral_network_media_open");
    }

    /** Join the socket open_media() gave to `call`'s media, once it has started; its media handle. */
    Handle attach_media(std::string_view address, const Call &call)
    {
        Handle media = call.media();
        detail::check(sipral_network_media_attach(state_->stack, address.data(), address.size(), call.handle(), media),
                      "sipral_network_media_attach");
        return media;
    }

    /** One frame of this end's audio for `media`, sent by the networking component. */
    void capture(Handle media, const std::int16_t *samples, std::size_t count)
    {
        detail::check(sipral_network_media_capture(state_->stack, media, now_ms(), samples, count),
                      "sipral_network_media_capture");
    }

    /** Close the socket open_media() gave. */
    void close_media(std::string_view address)
    {
        detail::check(sipral_network_media_close(state_->stack, address.data(), address.size()),
                      "sipral_network_media_close");
    }

    /** One turn of the networking component's loop, waiting at most `wait_ms` for something to arrive. */
    void run(std::uint32_t wait_ms)
    {
        state_->settle(sipral_network_run(state_->stack, now_ms(), wait_ms), "sipral_network_run");
    }

    /** See, change or drop every SIP message on its way out and in; an empty function removes the hook.
     * It runs inside the stack's lock: it must not call into this stack. */
    void set_message_hook(std::function<Verdict(const Hooked &)> hook)
    {
        state_->hook = std::move(hook);
        detail::check(sipral_stack_message_hook(state_->stack, state_->hook ? &Stack::ask : nullptr,
                                                state_->hook ? state_.get() : nullptr),
                      "sipral_stack_message_hook");
    }

    Account add_account(const AccountOptions &options)
    {
        sipral_account_config_t config{};
        config.size = sizeof config;
        auto text = [](const std::string &value) { return value.empty() ? nullptr : value.data(); };
        config.aor = text(options.aor);
        config.aor_len = options.aor.size();
        config.registrar = text(options.registrar);
        config.registrar_len = options.registrar.size();
        config.contact = text(options.contact);
        config.contact_len = options.contact.size();
        config.registrar_address = text(options.registrar_address);
        config.registrar_address_len = options.registrar_address.size();
        config.server_uri = text(options.server_uri);
        config.server_uri_len = options.server_uri.size();
        config.server_naptr = options.server_naptr ? SIPRAL_TOGGLE_ON : SIPRAL_TOGGLE_DEFAULT;
        config.stream_protocol = options.stream_protocol;
        config.srtp = options.srtp;
        config.auth_user = text(options.auth_user);
        config.auth_user_len = options.auth_user.size();
        config.auth_password = text(options.auth_password);
        config.auth_password_len = options.auth_password.size();
        Handle account = SIPRAL_HANDLE_NONE;
        detail::check(sipral_account_add(state_->stack, &config, &account), "sipral_account_add");
        return Account(state_->stack, account);
    }

    /** A call an event named, offered or placed. */
    Call call(Handle call) const noexcept { return Call(state_->stack, call); }

private:
    struct State {
        Handle stack = SIPRAL_HANDLE_NONE;
        bool network = false;
        std::string bind_address;
        std::function<void(const Event &)> on_event;
        std::function<Verdict(const Hooked &)> hook;
        /** The first exception a handler threw, rethrown once the library has returned. */
        std::exception_ptr thrown;

        void settle(sipral_status_t status, const char *call)
        {
            if (thrown) {
                std::rethrow_exception(std::exchange(thrown, nullptr));
            }
            detail::check(status, call);
        }
    };

    static void deliver(const sipral_event_t *event, void *user_data)
    {
        auto *state = static_cast<State *>(user_data);
        if (event == nullptr || !state->on_event || state->thrown) {
            return;
        }
        try {
            state->on_event(Event(*event));
        } catch (...) {
            state->thrown = std::current_exception();
        }
    }

    static std::uint32_t ask(const sipral_hooked_message_t *hooked, void *user_data)
    {
        auto *state = static_cast<State *>(user_data);
        if (hooked == nullptr || !state->hook) {
            return SIPRAL_HOOK_KEEP;
        }
        try {
            Hooked message{hooked->direction == SIPRAL_HOOK_OUTGOING, static_cast<sipral_transport_t>(hooked->transport),
                           std::string_view(hooked->remote, hooked->remote_len),
                           std::string_view(reinterpret_cast<const char *>(hooked->message), hooked->message_len)};
            Verdict verdict = state->hook(message);
            if (verdict.answer() == SIPRAL_HOOK_REPLACE) {
                const std::string &bytes = verdict.replacement();
                if (sipral_hooked_message_replace(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()) !=
                    SIPRAL_STATUS_OK) {
                    return SIPRAL_HOOK_KEEP;
                }
            }
            return verdict.answer();
        } catch (...) {
            if (!state->thrown) {
                state->thrown = std::current_exception();
            }
            return SIPRAL_HOOK_KEEP;
        }
    }

    void release() noexcept
    {
        if (state_ && state_->stack != SIPRAL_HANDLE_NONE) {
            if (state_->network) {
                sipral_network_stop(state_->stack);
            }
            if (state_->hook) {
                sipral_stack_message_hook(state_->stack, nullptr, nullptr);
            }
            sipral_stack_destroy(state_->stack);
            state_->stack = SIPRAL_HANDLE_NONE;
        }
    }

    std::unique_ptr<State> state_;
};

} // namespace sipral

#endif
