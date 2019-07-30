/*
 * A public, plain-C interface for client_limits module
 */

#ifndef THREEPROXY_CLIENT_LIMITS_H
#define THREEPROXY_CLIENT_LIMITS_H

#include "structures.h"
#include "proxy.h"

struct client_limits_info_t;

struct client_limits_params_t {
	// Band-limit for incoming traffic.
	// Value 0 means that band-limit is not set.
	unsigned in_rate;
	// Band-limit for outgoing traffic.
	// Value 0 means that band-limit is not set.
	unsigned out_rate;
};

// NOTE: returns NULL pointer in the case of an error.
struct client_limits_info_t *
client_limits_make(
	struct clientparam * client,
	const struct client_limits_params_t * limits);

// NOTE: it's safe to pass NULL as 'what'.
void
client_limits_release(
	struct clientparam * client,
	struct client_limits_info_t * what);

struct bandlim *
client_limits_bandlim(
	struct client_limits_info_t * what,
	CLIENT_BANDLIM_DIR direction);

//FIXME: should the following stuff be moved to a different header file?
typedef enum {
	// User successfully authentificated.
	authsubsys_auth_successful,
	// User denied by authentification entity.
	authsubsys_auth_denied,
	// Authentification operation failed by some reason.
	// We can tell is this user allowed or denied.
	authsubsys_auth_failed
} authsubsys_auth_result_t;

authsubsys_auth_result_t
authsubsys_authentificate_user(
	struct clientparam * client);

#endif

