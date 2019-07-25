/*
 * The main part of client limits implementation.
 */

extern "C" {

#include "client_limits.h"

}

#include <map>
#include <string>
#include <tuple>

#include <cstdio>

namespace client_limits {

struct key_t {
	// User name of client's IP.
	std::string client_id_;
	// External IP or service port.
	std::string service_id_;
};

bool
operator<(const key_t & a, const key_t & b) noexcept {
	return std::tie(a.client_id_, a.service_id_) <
			std::tie(b.client_id_, b.service_id_);
}

std::string
make_client_id(const clientparam * client) {
	const char * username = reinterpret_cast<char *>(client->username);

	if(!username) {
		// An IP address should be used instead of a client name.
		char string_ip[INET6_ADDRSTRLEN];
		username = inet_ntop(*SAFAMILY(&client->sincr),
				SAADDR(&client->sincr),
				string_ip, INET6_ADDRSTRLEN);
		if(!username) {
			throw std::runtime_error("unable to convert client IP to string");
		}
	}

	return username;
}

using limits_map_t = std::map<key_t, client_limits_info_t>;

limits_map_t limits_map;

class lock_guard_t {
	pthread_mutex_t & lock_;
public :
	lock_guard_t(pthread_mutex_t & lock) noexcept : lock_{lock} {
		pthread_mutex_lock(&lock_);
	}
	~lock_guard_t() noexcept {
		pthread_mutex_unlock(&lock_);
	}
};

template<typename Lambda, typename T>
T exception_catcher(const char * where, Lambda && lambda, T on_exception_value) {
	try {
		return lambda();
	}
	catch(const std::exception & x) {
		std::fprintf(stderr, "%s: exception caught: %s\n",
				where, x.what());
	}
	catch(...) {
		std::fprintf(stderr, "%s: unknown exception caught, "
				"details aren't available\n",
				where);
	}
	return on_exception_value;
}

template<typename T>
constexpr T* nullptr_of() noexcept { return static_cast<T*>(nullptr); }

} /* namespace client_limits */

using namespace client_limits;

extern "C" struct client_limits_info_t {
	bandlim in_limit_;
	bandlim out_limit_;

	unsigned usage_count_{1};

	limits_map_t::iterator position_;

	static bandlim
	make_bandlim(unsigned rate) noexcept {
		return { nullptr, nullptr, 0, 0, rate };
	}

	client_limits_info_t(const client_limits_params_t & p) noexcept
		: in_limit_{make_bandlim(p.in_rate)}
		, out_limit_{make_bandlim(p.out_rate)}
	{}
};

extern "C"
struct client_limits_info_t *
client_limits_make(
	const clientparam * client,
	const client_limits_params_t * limits) {

	return exception_catcher("client_limits_make", [&] {
			lock_guard_t lock{bandlim_mutex};

			client_limits::key_t client_key{make_client_id(client), "not-used-yet"};
			auto it = limits_map.find(client_key);
			if(it != limits_map.end()) {
				// Reuse existing client info.
				it->second.usage_count_ += 1u;
				return &it->second;
			}
			else {
				// A new client info should be created.
				auto ins_result = limits_map.emplace(
						client_key,
						client_limits_info_t{*limits});
				auto result = &(ins_result.first->second);
				// Interator to inserted item should be stored inside that item.
				// It allows cheap deletion of that item when it is no more needed.
				result->position_ = ins_result.first;

				return result;
			}
		},
		nullptr_of<client_limits_info_t>());
}

extern "C"
void
client_limits_release(client_limits_info_t * what) {
	if(!what)
		return;

	lock_guard_t lock{bandlim_mutex};

	what->usage_count_ -= 1;
	if(!what->usage_count_) {
printf("*** remove client_limits_info_t: %s, %s\n", what->position_->first.client_id_.c_str(), what->position_->first.service_id_.c_str());
		// This item is no more needed.
		limits_map.erase(what->position_);
	}
}

extern "C"
struct bandlim *
client_limits_bandlim(
	client_limits_info_t * what,
	CLIENT_BANDLIM_DIR direction) {

	if(!what)
		return nullptr;

	const auto handler = [what](bandlim & lim_info) {
		if(0 == lim_info.rate)
			// Band-limit is not set!
			return nullptr_of<bandlim>();
		else
			return &lim_info;
	};

	return CLIENT_BANDLIM_IN == direction ?
			handler(what->in_limit_) : handler(what->out_limit_);
}

