/*
 * The main part of client limits implementation.
 */

extern "C" {

#include "client_limits.h"

}

#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <algorithm>

#include <cstdio>

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

