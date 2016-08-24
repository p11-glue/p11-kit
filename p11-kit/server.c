/*
 * Copyright (C) 2014 Red Hat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "compat.h"
#include "debug.h"
#include "message.h"
#include "path.h"
#include "p11-kit.h"
#include "remote.h"
#include "unix-peer.h"
#include "tool.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_SIGHANDLER_T
#define SIGHANDLER_T sighandler_t
#elif HAVE_SIG_T
#define SIGHANDLER_T sig_t
#elif HAVE___SIGHANDLER_T
#define SIGHANDLER_T __sighandler_t
#else
typedef void (*sighandler_t)(int);
#define SIGHANDLER_T sighandler_t
#endif

static bool need_children_cleanup = false;
static bool terminate = false;
static unsigned children_avail = 0;
static bool quiet = false;

typedef struct {
	char *module_name;

	uid_t uid;
	gid_t gid;

	char *pkcs11_address;
	int pkcs11_socket;
} Server;

static SIGHANDLER_T
ocsignal (int signum, SIGHANDLER_T handler)
{
	struct sigaction new_action, old_action;

	new_action.sa_handler = handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction (signum, &new_action, &old_action);
	return old_action.sa_handler;
}

static void
cleanup_children (void)
{
	int status;
	pid_t pid;

	while ((pid = waitpid (-1, &status, WNOHANG)) > 0) {
		if (children_avail > 0)
			children_avail--;
		if (WIFSIGNALED (status)) {
			if (WTERMSIG (status) == SIGSEGV)
				p11_message ("child %u died with sigsegv", (unsigned)pid);
			else
				p11_message ("child %u died with signal %d", (unsigned)pid, (int)WTERMSIG (status));
		}
	}
	need_children_cleanup = false;
}

static void
handle_children (int signo)
{
	need_children_cleanup = true;
}

static void
handle_term (int signo)
{
	terminate = true;
}

static int
set_cloexec_on_fd (void *data,
                   int fd)
{
	int *max_fd = data;
	if (fd >= *max_fd)
		fcntl (fd, F_SETFD, FD_CLOEXEC);
	return 0;
}

static int
exec_external (int argc,
	       char *argv[])
{
	const char *private_dir;
	char *path;
	int rc;

	return_val_if_fail (argc >= 1, -1);

	private_dir = secure_getenv ("P11_KIT_PRIVATEDIR");
	if (!private_dir || !private_dir[0])
		private_dir = PRIVATEDIR;

	/* Add our libexec directory to the path */
	path = p11_path_build (private_dir, argv[0], NULL);
	return_val_if_fail (path != NULL, -1);

	argv[argc] = NULL;
	rc = execv (path, argv);

	free (path);
	return rc;
}

static int
create_socket (const char *address,
	       uid_t uid,
	       gid_t gid)
{
	int rc, sd;
	struct sockaddr_un sa;
	const char *socket_file;

	memset (&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;

	return_val_if_fail (strlen (address) < sizeof (sa.sun_path), -1);
	strncpy (sa.sun_path, address, sizeof (sa.sun_path));
	socket_file = sa.sun_path;

	remove (sa.sun_path);

	sd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		p11_message_err (errno, "could not create socket %s", socket_file);
		return -1;
	}

	umask (066);
	rc = bind (sd, (struct sockaddr *)&sa, SUN_LEN (&sa));
	if (rc == -1) {
		p11_message_err (errno, "could not create socket %s", socket_file);
		return -1;
	}

	if (uid != -1 && gid != -1) {
		rc = chown (socket_file, uid, gid);
		if (rc == -1) {
			p11_message_err (errno, "could not chown socket %s", socket_file);
			return -1;
		}
	}

	return sd;
}

static bool
check_credentials (int fd,
		   uid_t uid,
		   gid_t gid)
{
	int rc;
	uid_t tuid;
	gid_t tgid;

	rc = p11_get_upeer_id (fd, &tuid, &tgid, NULL);
	if (rc == -1) {
		p11_message_err (errno, "could not check uid from socket");
		close (fd);
		return false;
	}

	if (uid != -1 && uid != tuid) {
		p11_message ("connecting uid (%u) doesn't match expected (%u)",
			     (unsigned)tuid, (unsigned)uid);
		close (fd);
		return false;
	}

	if (gid != -1 && gid != tgid) {
		p11_message ("connecting gid (%u) doesn't match expected (%u)",
			     (unsigned)tgid, (unsigned)gid);
		close (fd);
		return false;
	}

	return true;
}

static Server *
server_new (const char *module_name, const char *socket_base, const char *socket_name, uid_t uid, gid_t gid)
{
	Server *server = calloc (1, sizeof (Server));
	char *name;

	server->module_name = strdup (module_name);
	return_val_if_fail (server->module_name != NULL, NULL);

	server->uid = uid;
	server->gid = gid;

	if (socket_name != NULL)
		name = strdup (socket_name);
	else if (asprintf (&name, "pkcs11-%d", getpid ()) < 0)
		return_val_if_reached (NULL);

	server->pkcs11_address = p11_path_build (socket_base, name, NULL);
	free (name);

	return_val_if_fail (server->pkcs11_address != NULL, NULL);
	server->pkcs11_socket = -1;

	return server;
}

static void
server_free (Server *server)
{
	free (server->module_name);
	free (server->pkcs11_address);
	if (server->pkcs11_socket >= 0)
		close (server->pkcs11_socket);
	free (server);
}

static int
server_loop (Server *server,
	     bool foreground,
	     struct timespec *timeout)
{
	int ret = 1, rc;
	int cfd;
	pid_t pid;
	socklen_t sa_len;
	struct sockaddr_un sa;
	fd_set rd_set;
	sigset_t emptyset, blockset;
	char *args[] = { "p11-kit-remote", NULL, NULL };
	int max_fd;
	int errn;

	sigemptyset (&blockset);
	sigemptyset (&emptyset);
	sigaddset (&blockset, SIGCHLD);
	sigaddset (&blockset, SIGTERM);
	sigaddset (&blockset, SIGINT);
	ocsignal (SIGCHLD, handle_children);
	ocsignal (SIGTERM, handle_term);
	ocsignal (SIGINT, handle_term);

	server->pkcs11_socket = create_socket (server->pkcs11_address, server->uid, server->gid);
	if (server->pkcs11_socket == -1)
		return 1;

	/* run as daemon */
	if (!foreground) {
		pid = fork ();
		switch (pid) {
		case -1:
			p11_message_err (errno, "could not fork() to daemonize");
			return 1;
		case 0:
			break;
		default:
			_exit (0);
		}
		if (setsid () == -1) {
			p11_message_err (errno, "could not create a new session");
			return 1;
		}
	}

	rc = listen (server->pkcs11_socket, 1024);
	if (rc == -1) {
		p11_message_err (errno, "could not listen to socket %s", server->pkcs11_address);
		return 1;
	}

	sigprocmask (SIG_BLOCK, &blockset, NULL);

	if (!quiet) {
		char *path;

		path = p11_path_encode (server->pkcs11_address);
		printf ("P11_KIT_SERVER_ADDRESS=unix:path=%s\n", path);
		free (path);
		printf ("P11_KIT_SERVER_PID=%d\n", getpid ());
	}

	/* accept connections */
	ret = 0;
	for (;;) {
		if (need_children_cleanup)
			cleanup_children ();

		if (terminate)
			break;

		FD_ZERO (&rd_set);
		FD_SET (server->pkcs11_socket, &rd_set);

		ret = pselect (server->pkcs11_socket + 1, &rd_set, NULL, NULL, timeout, &emptyset);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret == 0 && children_avail == 0) { /* timeout */
			p11_message ("no connections to %s for %lu secs, exiting", server->pkcs11_address, timeout->tv_sec);
			break;
		}

		if (FD_ISSET (server->pkcs11_socket, &rd_set)) {
			sa_len = sizeof (sa);
			cfd = accept (server->pkcs11_socket, (struct sockaddr *)&sa, &sa_len);
			if (cfd == -1) {
				if (errno != EINTR)
					p11_message_err (errno, "could not accept from socket %s", server->pkcs11_address);
				continue;
			}

			if (!check_credentials (cfd, server->uid, server->gid))
				continue;

			pid = fork ();
			switch (pid) {
			case -1:
				p11_message_err (errno, "failed to fork for accept");
				continue;
			/* Child */
			case 0:
				sigprocmask (SIG_UNBLOCK, &blockset, NULL);
				if (dup2 (cfd, STDIN_FILENO) < 0 ||
				    dup2 (cfd, STDOUT_FILENO) < 0) {
					errn = errno;
					p11_message_err (errn, "couldn't dup file descriptors in remote child");
					_exit (errn);
				}

				/* Close file descriptors, except for above on exec */
				max_fd = STDERR_FILENO + 1;
				fdwalk (set_cloexec_on_fd, &max_fd);

				/* Execute 'p11-kit remote'; this shouldn't return */
				args[1] = (char *) server->module_name;
				exec_external (2, args);

				errn = errno;
				p11_message_err (errn, "couldn't execute 'p11-kit remote' for module '%s'", server->module_name);
				_exit (errn);
			default:
				children_avail++;
				break;
			}
			close (cfd);
		}
	}

	remove (server->pkcs11_address);

	return ret;
}

int
main (int argc,
      char *argv[])
{
	char *module_name;
	char *socket_base;
	uid_t uid = -1, run_as_uid = -1;
	gid_t gid = -1, run_as_gid = -1;
	int opt;
	const struct passwd *pwd;
	const struct group *grp;
	bool foreground = false;
	struct timespec *timeout = NULL, ts;
	const char *name = NULL;
	Server *server;
	int ret;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_user = 'u',
		opt_group = 'g',
		opt_run_as_user = 'a',
		opt_run_as_group = 'z',
		opt_foreground = 'f',
		opt_timeout = 't',
		opt_name = 'n',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "foreground", no_argument, NULL, opt_foreground },
		{ "user", required_argument, NULL, opt_user },
		{ "group", required_argument, NULL, opt_group },
		{ "run-as-user", required_argument, NULL, opt_run_as_user },
		{ "run-as-group", required_argument, NULL, opt_run_as_group },
		{ "timeout", required_argument, NULL, opt_timeout },
		{ "name", required_argument, NULL, opt_name },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit server <token> [<directory>]" },
		{ opt_foreground, "run the server in foreground" },
		{ opt_user, "specify user who can connect to the socket" },
		{ opt_group, "specify group who can connect to the socket" },
		{ opt_run_as_user, "specify user who runs the server" },
		{ opt_run_as_group, "specify group who runs the server" },
		{ opt_timeout, "exit if no connection until the given timeout" },
		{ opt_name, "specify name of the socket (default: pkcs11-<pid>" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_quiet:
			quiet = true;
			break;
		case opt_timeout:
			ts.tv_sec = atoi (optarg);
			ts.tv_nsec = 0;
			timeout = &ts;
			break;
		case opt_name:
			name = optarg;
			break;
		case opt_group:
			grp = getgrnam (optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			gid = grp->gr_gid;
			break;
		case opt_user:
			pwd = getpwnam (optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			uid = pwd->pw_uid;
			break;
		case opt_run_as_group:
			grp = getgrnam (optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			run_as_gid = grp->gr_gid;
			break;
		case opt_run_as_user:
			pwd = getpwnam (optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			run_as_uid = pwd->pw_uid;
			break;
		case opt_foreground:
			foreground = true;
			break;
		case opt_help:
		case '?':
			p11_tool_usage (usages, options);
			return 0;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (!(argc >= 1 && argc <= 2)) {
		p11_tool_usage (usages, options);
		return 2;
	}

	module_name = argv[0];

	if (argc == 2)
		socket_base = argv[1];
	else {
		const char *runtime_dir = secure_getenv ("XDG_RUNTIME_DIR");
		if (!runtime_dir || !runtime_dir[0]) {
			p11_message_err (errno, "cannot determine runtime directory");
			return 1;
		}
		socket_base = p11_path_build (runtime_dir, "p11-kit", NULL);
		return_val_if_fail (socket_base != NULL, 1);
		mkdir (socket_base, 0700);
	}

	if (run_as_gid != -1) {
		if (setgid (run_as_gid) == -1) {
			p11_message_err (errno, "cannot set gid to %u", (unsigned)run_as_gid);
			return 1;
		}

		if (setgroups (1, &run_as_gid) == -1) {
			p11_message_err (errno, "cannot setgroups to %u", (unsigned)run_as_gid);
			return 1;
		}
	}

	if (run_as_uid != -1) {
		if (setuid (run_as_uid) == -1) {
			p11_message_err (errno, "cannot set uid to %u", (unsigned)run_as_uid);
			return 1;
		}
	}

	server = server_new (module_name, socket_base, name, uid, gid);
	ret = server_loop (server, foreground, timeout);
	server_free (server);
	remove (socket_base);

	return ret;
}
