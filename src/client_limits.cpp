/*
 * The main part of client limits implementation.
 */

extern "C" {

#include "client_limits.h"

}

#include "variant.hpp"

#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <algorithm>
#include <chrono>
#include <mutex>

#include <cstdio>

using namespace nonstd;

using steady_clock = std::chrono::steady_clock;

//NOTE: the following code borrowed from SObjectizer project
// https://bitbucket.org/sobjectizerteam/sobjectizer
namespace so_5 {

namespace details {

namespace rollback_on_exception_details {

/*!
 * \since
 * v.5.5.4
 *
 * \brief Helper template class for do rollback actions automatically
 * in the destructor.
 *
 * \tparam L type of lambda with rollback actions.
 */
template< typename L >
class rollbacker_t
	{
		L & m_action;
		bool m_commited = false;

	public :
		inline rollbacker_t( L & action ) : m_action( action ) {}
		inline ~rollbacker_t() { if( !m_commited ) m_action(); }

		inline void commit() { m_commited = true; }
	};

template< typename Result, typename Main_Action, typename Rollback_Action >
struct executor
	{
		static Result
		exec(
			Main_Action main_action,
			rollbacker_t< Rollback_Action > & rollback )
			{
				auto r = main_action();
				rollback.commit();

				return r;
			}
	};

template< typename Main_Action, typename Rollback_Action >
struct executor< void, Main_Action, Rollback_Action >
	{
		static void
		exec( 
			Main_Action main_action,
			rollbacker_t< Rollback_Action > & rollback )
			{
				main_action();
				rollback.commit();
			}
	};

} /* namespace rollback_on_exception_details */

/*!
 * \since
 * v.5.5.4
 *
 * \brief Helper function for do some action with rollback in the case of
 * an exception.
 *
 * \tparam Main_Action type of lambda with main action.
 * \tparam Rollback_Action type of lambda with rollback action.
 */
template< typename Main_Action, typename Rollback_Action >
auto
do_with_rollback_on_exception(
	Main_Action main_action,
	Rollback_Action rollback_action )
	-> decltype(main_action())
	{
		using result_type = decltype(main_action());

		using namespace rollback_on_exception_details;

		rollbacker_t< Rollback_Action > rollbacker{ rollback_action };

		return executor< result_type, Main_Action, Rollback_Action >::exec(
				main_action, rollbacker );
	}

} /* namespace details */

} /* namespace so_5 */

using namespace so_5::details;

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

template<typename Addr>
std::string
ip_to_string(const Addr & addr) {
	char string_ip[INET6_ADDRSTRLEN];
	const char * ip = inet_ntop(*SAFAMILY(&addr), SAADDR(&addr),
			string_ip, INET6_ADDRSTRLEN);
	if(!ip) {
		throw std::runtime_error("unable to convert client IP to string");
	}
	return ip;
}

std::string
make_client_id(const clientparam * client) {
	const char * username = reinterpret_cast<char *>(client->username);

	if(username) 
		return username;
	else
		// An IP address should be used instead of a client name.
		return ip_to_string(client->sincr);
}

#ifndef NOIPV6
const sockaddr_in6 &
get_service_ext_address_reference(const clientparam * client) {
	// It seems that in the case of IPv4 address the value of extsa6
	// will be null. In that case extsa is used.
	// There is no any descriptions in code found but it was proved
	// by some testing.
	if(SAISNULL(&client->srv->extsa6))
		return client->srv->extsa;
	else
		return client->srv->extsa6;
}
#else
const sockaddr_in &
get_service_ext_address_reference(const clientparam * client) {
	return client->srv->extsa;
}
#endif

std::string
make_service_id(const clientparam * client) {
	return "ext_ip="
		+ ip_to_string(get_service_ext_address_reference(client))
		+ ";port="
		+ std::to_string(ntohs(*SAPORT(&client->srv->intsa)));
}

using limits_map_t = std::map<key_t, client_limits_info_t>;

limits_map_t limits_map;

using clientparam_ptr_container_t = std::vector<clientparam *>;

class lock_guard_t {
	pthread_mutex_t & lock_;
public :
	lock_guard_t(pthread_mutex_t & lock) noexcept : lock_(lock) {
		pthread_mutex_lock(&lock_);
	}
	~lock_guard_t() noexcept {
		pthread_mutex_unlock(&lock_);
	}
};

template<typename Lambda, typename T>
T exception_catcher(const char * where, Lambda && lambda, T on_exception_value) noexcept {
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

//
// Parts related to authsubsys
//

class authsubsys_t {
	std::mutex lock_;

	struct not_authentificated_user_t {
		std::vector<steady_clock::time_point> failed_attemps_timestamps_;

		not_authentificated_user_t(
				unsigned max_failed_attempts) {
			failed_attemps_timestamps_.reserve(max_failed_attempts);
		}
	};

	struct authentificated_user_t {
		// Optional band-limits.
		unsigned personal_bandlimin_rate_{0u};
		unsigned personal_bandlimout_rate_{0u};
	};

	struct banned_user_t {
		// NOTE. There is no actual data for banned user.
	};

	using user_info_variant_t = variant<
			not_authentificated_user_t,
			authentificated_user_t,
			banned_user_t>;

	struct user_info_t {
		// A time point at that this information should be invalidated.
		steady_clock::time_point expires_at_;

		// An information about the user.
		user_info_variant_t info_;

		user_info_t() = default;

		template<typename Auth_Info>
		user_info_t(
			steady_clock::time_point expires_at,
			Auth_Info auth_info)
			: expires_at_(expires_at)
			, info_(std::move(auth_info))
		{}
	};

	using client_map_t = std::map<key_t, user_info_t>;

	// How many failed attempts user can do before he/she will be banned.
	unsigned max_failed_attempts_{1};
	// A time-window inside that failed attempts are counted.
	std::chrono::seconds allowed_time_window_{0};
	// Ban time interval.
	std::chrono::seconds ban_period_{2};

	// How much time the info about successful authentification should be
	// stored and used in cache.
	std::chrono::seconds success_expiration_time_{0};

	client_map_t clients_;

	// Cache cleanup interval.
	const std::chrono::seconds cleanup_period_{60};
	// Last time when cache was cleaned.
	steady_clock::time_point last_cleanup_at_{steady_clock::now()};

	static bool
	is_banned_user(const user_info_t & info) noexcept;

	static bool
	is_authentificated_user(const user_info_t & info) noexcept;

	// For the case when already authentificated client is present in
	// the cache.
	// Note: this method should be called only when lock_ object
	// is acquired.
	authsubsys_auth_result_t
	complete_successful_auth(
		clientparam * client,
		user_info_t & existing_info);

	// For the case when info about successfuly authenticated client
	// should be created in the cache.
	// Note: this method should be called only when lock_ object
	// is acquired.
	authsubsys_auth_result_t
	complete_successful_auth(
		const steady_clock::time_point now,
		clientparam * client,
		key_t client_key);

	// For the case when info about denied client
	// should be created in the cache.
	// Note: this method should be called only when lock_ object
	// is acquired.
	authsubsys_auth_result_t
	complete_denied_auth(
		const steady_clock::time_point now,
		int authfunc_result,
		clientparam * client,
		key_t client_key);

	// Note: this method should be called only when lock_ object
	// is acquired.
	void
	clean_cache_if_necessary(
		const steady_clock::time_point now) noexcept;

public:
	authsubsys_auth_result_t
	authentificate_user(clientparam * client);

	void
	setup_times(
		std::chrono::seconds success_expiration_time,
		std::chrono::seconds allowed_time_window,
		unsigned max_failed_attempts,
		std::chrono::seconds ban_period) noexcept;
};

bool
authsubsys_t::is_banned_user(const user_info_t & info) noexcept {
	return 2u == info.info_.index();
}

bool
authsubsys_t::is_authentificated_user(const user_info_t & info) noexcept {
	return 1u == info.info_.index();
}

authsubsys_auth_result_t
authsubsys_t::complete_successful_auth(
		clientparam * client,
		user_info_t & existing_info) {
	const auto & i = get<authentificated_user_t>(existing_info.info_);

	// Values of personal band-limits must be taken to a new client.
	client->personal_bandlimin_rate = i.personal_bandlimin_rate_;
	client->personal_bandlimout_rate = i.personal_bandlimout_rate_;

	return authsubsys_auth_successful;
}

authsubsys_auth_result_t
authsubsys_t::complete_successful_auth(
		const steady_clock::time_point now,
		clientparam * client,
		key_t client_key) {
	authentificated_user_t auth_info;

	auth_info.personal_bandlimin_rate_ = client->personal_bandlimin_rate;
	auth_info.personal_bandlimout_rate_ = client->personal_bandlimout_rate;

	const auto expires_at = now + success_expiration_time_;
	const auto ins_result = clients_.emplace(
			std::move(client_key),
			user_info_t{expires_at, auth_info});
	if(!ins_result.second) {
		// The value wasn't inserted in the map. Old item should be modified.
		user_info_t & old_info = ins_result.first->second;
		// This is the expiration time of a new 'successful' info.
		// The previous info was 'not_authentificated_user_t' and its
		// expiration time is no more valid.
		old_info.expires_at_ = expires_at;
		old_info.info_ = auth_info;
	}

	return authsubsys_auth_successful;
}

authsubsys_auth_result_t
authsubsys_t::complete_denied_auth(
		const steady_clock::time_point now,
		int authfunc_result,
		clientparam * client,
		key_t client_key) {
	// Actual actions should be performed only if we have RES_CODE_AUTH_DENY.
	// All other failed attempts should be ignored.
	if(RES_CODE_AUTH_DENY != authfunc_result)
		return authsubsys_auth_failed;

	auto it = clients_.find(client_key);
	if(it == clients_.end()) {
		// A new info should be created.
		const auto ins_result = clients_.emplace(
				std::move(client_key),
				user_info_t{
						now + allowed_time_window_,
						not_authentificated_user_t{max_failed_attempts_}});
		it = ins_result.first;
	}

	auto & user_info = it->second;
	auto * auth_info = &(get<not_authentificated_user_t>(user_info.info_));

	auth_info->failed_attemps_timestamps_.push_back(now);
	if(max_failed_attempts_ == auth_info->failed_attemps_timestamps_.size()) {
		// Is this the case for a ban?
		if(auth_info->failed_attemps_timestamps_.front() + allowed_time_window_
				>= now) {
			// User should be banned!
			user_info.expires_at_ = now + ban_period_;
			user_info.info_ = banned_user_t{};
		}
		else {
			// The first item in failed_attemps_timestamps_ is no more needed.
			auth_info->failed_attemps_timestamps_.erase(
					auth_info->failed_attemps_timestamps_.begin());
		}
	}

	if(!is_banned_user(user_info)) {
		// Expiration time should be updated.
		user_info.expires_at_ = now + allowed_time_window_;
	}

	return authsubsys_auth_denied;
}

void
authsubsys_t::clean_cache_if_necessary(
		const steady_clock::time_point now) noexcept {
	if(last_cleanup_at_ + cleanup_period_ > now)
		return; // Nothing to do.

	auto it = clients_.begin();
	while(it != clients_.end()) {
		if(it->second.expires_at_ <= now) {
			it = clients_.erase(it);
		}
		else
			++it;
	}
}

authsubsys_auth_result_t
authsubsys_t::authentificate_user(clientparam * client) {
	key_t client_key{make_client_id(client), make_service_id(client)};

	const auto current_time = steady_clock::now();

	// Try to find previous information about that client.
	{
		std::lock_guard<std::mutex> l{lock_};
		clean_cache_if_necessary(current_time);

		auto it = clients_.find(client_key);
		if(it != clients_.end()) {
			if(it->second.expires_at_ <= current_time) {
				// Information about that client already expired and should
				// be removed.
				clients_.erase(it);
			}
			else if(is_banned_user(it->second)) {
				return authsubsys_auth_denied;
			}
			else if(is_authentificated_user(it->second)) {
				// Some information should be updated in 'client' object.
				return complete_successful_auth(client, it->second);
			}
		}
	}

	// Actual authentication should be performed here.
	int authfunc_result = RES_CODE_AUTH_FAILED;
	// Iterate over defined authmethods for the service.
	for(auth * authfuncs=client->srv->authfuncs;
			authfuncs;
			authfuncs = authfuncs->next) {
		authfunc_result = authfuncs->authenticate ?
				(*authfuncs->authenticate)(client) : 0;
		if(!authfunc_result) {
			if(authfuncs->authorize &&
					(authfunc_result = (*authfuncs->authorize)(client))) {
				break; // There is no sense to go to the next authfunc.
			}
		}
	}

	// The object's lock should be acquired to complete the operation.
	{
		std::lock_guard<std::mutex> lock{lock_};

		return RES_CODE_SUCCESS == authfunc_result ?
				complete_successful_auth(
						current_time, client, std::move(client_key)) :
				complete_denied_auth(
						current_time, authfunc_result, client, std::move(client_key));
	}
}

void
authsubsys_t::setup_times(
		std::chrono::seconds success_expiration_time,
		std::chrono::seconds allowed_time_window,
		unsigned max_failed_attempts,
		std::chrono::seconds ban_period) noexcept {
	success_expiration_time_ = success_expiration_time;
	allowed_time_window_ = allowed_time_window;
	max_failed_attempts_ = max_failed_attempts;
	ban_period_ = ban_period;
}

//
// An instance of authsubsys.
//
authsubsys_t authsubsys_instance;

} /* namespace client_limits */

using namespace client_limits;

extern "C" struct client_limits_info_t {
	bandlim in_limit_;
	bandlim out_limit_;

	// Pointers to actual connections of that client.
	// If that vector is empty then there is no actual connections.
	clientparam_ptr_container_t connections_;

	limits_map_t::iterator position_;

	static bandlim
	make_bandlim(unsigned rate) noexcept {
		return { nullptr, nullptr, 0, 0, rate };
	}

	client_limits_info_t(const client_limits_params_t & p) noexcept
		: in_limit_(make_bandlim(p.in_rate))
		, out_limit_(make_bandlim(p.out_rate))
	{}
};

namespace {

bandlim *
query_appropriate_bandlim_ptr(bandlim & lim_info) noexcept {
	if(0 == lim_info.rate)
		// Band-limit is not set!
		return nullptr_of<bandlim>();
	else
		return &lim_info;
};

void
handle_limits_change_if_any(
		client_limits_info_t & info,
		const client_limits_params_t & new_limits) noexcept {

	const auto reconfig_limit_if_necessary = [](
			bandlim & lim_info,
			const unsigned new_rate) {
		if(lim_info.rate != new_rate) {
			lim_info.rate = new_rate;
			lim_info.basetime = 0;
			lim_info.nexttime = 0;
		}
	};

	const auto old_pointers = std::make_tuple(
			query_appropriate_bandlim_ptr(info.in_limit_),
			query_appropriate_bandlim_ptr(info.out_limit_));

	reconfig_limit_if_necessary(info.in_limit_, new_limits.in_rate);
	reconfig_limit_if_necessary(info.out_limit_, new_limits.out_rate);

	const auto new_pointers = std::make_tuple(
			query_appropriate_bandlim_ptr(info.in_limit_),
			query_appropriate_bandlim_ptr(info.out_limit_));

	if(old_pointers != new_pointers) {
		// Pointers to bandlim objects must be updated.
		// We can do it becasuse handle_limits_change_if_any is called
		// when bandlim_mutex is acquired.
		for(auto * client : info.connections_) {
			client->personal_bandlimin = std::get<0>(new_pointers);
			client->personal_bandlimout = std::get<1>(new_pointers);
			initbandlims(client);
		}
	}
}

} /* namespace anonymous */

extern "C"
struct client_limits_info_t *
client_limits_make(
	clientparam * client,
	const client_limits_params_t * limits) {

	return exception_catcher("client_limits_make", [&] {
			lock_guard_t lock{bandlim_mutex};

			client_limits::key_t client_key{
					make_client_id(client),
					make_service_id(client)
			};
			auto it = limits_map.find(client_key);
			if(it != limits_map.end()) {
				// Reuse existing client info.

				// Another connection should be stored.
				it->second.connections_.push_back(client);

				handle_limits_change_if_any(it->second, *limits);

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

				// Another connection should be stored.
				// In the case of an exception the modification of
				// limits_map should be rolled back.
				return do_with_rollback_on_exception(
						[&] {
							result->connections_.push_back(client);
							return result;
						},
						[&] { limits_map.erase(ins_result.first); });
			}
		},
		nullptr_of<client_limits_info_t>());
}

extern "C"
void
client_limits_release(
		clientparam * client,
		client_limits_info_t * what) {

	if(!what)
		return;

	lock_guard_t lock{bandlim_mutex};

	// Remove this connection from known connections.
	what->connections_.erase(
			std::remove(
					what->connections_.begin(), what->connections_.end(), client),
			what->connections_.end());

	if(what->connections_.empty()) {
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

	return CLIENT_BANDLIM_IN == direction ?
			query_appropriate_bandlim_ptr(what->in_limit_) :
			query_appropriate_bandlim_ptr(what->out_limit_);
}

extern "C"
authsubsys_auth_result_t
authsubsys_authentificate_user(struct clientparam * client) {
	return exception_catcher("authsubsys_authentificate_user", [&] {
			return authsubsys_instance.authentificate_user(client);
		},
		authsubsys_auth_failed);
}

extern "C"
void
authsubsys_setup_times(
		unsigned success_expiration_time_sec,
		unsigned allowed_time_window_sec,
		unsigned max_failed_attempts,
		unsigned ban_period_sec) {
	authsubsys_instance.setup_times(
			std::chrono::seconds{success_expiration_time_sec},
			std::chrono::seconds{allowed_time_window_sec},
			max_failed_attempts,
			std::chrono::seconds{ban_period_sec});
}
