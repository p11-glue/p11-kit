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
#include "tool.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_UNIX

#include "unix-peer.h"
#include <grp.h>
#include <pwd.h>
#include <signal.h>
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

#endif /* OS_UNIX */

typedef struct {
	const char **tokens;
	size_t n_tokens;
	const char *provider;

	const char *socket_name;

#ifdef OS_UNIX
	uid_t uid;
	gid_t gid;

	int socket;
#endif /* OS_UNIX */

#ifdef OS_WIN32
	CK_FUNCTION_LIST *module;
#endif /* OS_WIN32 */
} Server;

static void
server_free (Server *server)
{
	if (server == NULL)
		return;

#ifdef OS_UNIX
	if (server->socket >= 0)
		close (server->socket);
#endif /* OS_UNIX */

#ifdef OS_WIN32
	if (server->module)
		p11_kit_module_release (server->module);
#endif /* OS_WIN32 */

	free (server);
}

static Server *
server_new (const char **tokens, size_t n_tokens, const char *provider,
	    const char *socket_name)
{
	Server *server;

	return_val_if_fail (tokens, NULL);
	return_val_if_fail (n_tokens > 0, NULL);
	return_val_if_fail (socket_name, NULL);

	server = calloc (1, sizeof (Server));

	if (server == NULL)
		return NULL;

	server->tokens = tokens;
	server->n_tokens = n_tokens;
	server->provider = provider;
	server->socket_name = socket_name;

#ifdef OS_UNIX
	server->socket = -1;
#endif /* OS_UNIX */

#ifdef OS_WIN32
	/* On Windows, we need to load module by ourselves as we don't
	 * launch "p11-kit remote" */
	if (strncmp (tokens[0], "pkcs11:", 7) == 0) {
		if (server->provider) {
			server->module = p11_kit_module_load (server->provider, 0);
			if (server->module == NULL)
				return NULL;
		}
	} else {
		server->module = p11_kit_module_load (tokens[0], 0);
		if (server->module == NULL)
			return NULL;
	}
#endif /* OS_WIN32 */

	return server;
}

#ifdef OS_UNIX

static bool need_children_cleanup = false;
static bool terminate = false;
static unsigned children_avail = 0;
static bool quiet = false;

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
	char **args;
	size_t n_args, i;
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

	server->socket = create_socket (server->socket_name, server->uid, server->gid);
	if (server->socket == -1)
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

	rc = listen (server->socket, 1024);
	if (rc == -1) {
		p11_message_err (errno, "could not listen to socket %s", server->socket_name);
		return 1;
	}

	sigprocmask (SIG_BLOCK, &blockset, NULL);

	if (!quiet) {
		char *path;

		path = p11_path_encode (server->socket_name);
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
		FD_SET (server->socket, &rd_set);

		ret = pselect (server->socket + 1, &rd_set, NULL, NULL, timeout, &emptyset);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret == 0 && children_avail == 0) { /* timeout */
			p11_message ("no connections to %s for %lu secs, exiting", server->socket_name, timeout->tv_sec);
			break;
		}

		if (FD_ISSET (server->socket, &rd_set)) {
			sa_len = sizeof (sa);
			cfd = accept (server->socket, (struct sockaddr *)&sa, &sa_len);
			if (cfd == -1) {
				if (errno != EINTR)
					p11_message_err (errno, "could not accept from socket %s", server->socket_name);
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
				args = calloc (3 + server->n_tokens + 1, sizeof (char *));
				if (args == NULL) {
					errn = errno;
					p11_message_err (errn, "couldn't allocate memory for 'p11-kit remote' arguments");
					_exit (errn);
				}

				n_args = 0;
				args[n_args] = "p11-kit-remote";
				n_args++;

				if (server->provider) {
					args[n_args] = "--provider";
					n_args++;
					args[n_args] = (char *)server->provider;
					n_args++;
				}

				for (i = 0; i < server->n_tokens; i++, n_args++)
					args[n_args] = (char *)server->tokens[i];

				exec_external (n_args, args);
				free (args);

				errn = errno;
				p11_message_err (errn, "couldn't execute 'p11-kit remote'");
				_exit (errn);
			default:
				children_avail++;
				break;
			}
			close (cfd);
		}
	}

	remove (server->socket_name);

	return ret;
}

int
main (int argc,
      char *argv[])
{
	char *socket_base = NULL, *socket_name = NULL;
	uid_t uid = -1, run_as_uid = -1;
	gid_t gid = -1, run_as_gid = -1;
	int opt;
	const struct passwd *pwd;
	const struct group *grp;
	bool foreground = false;
	struct timespec *timeout = NULL, ts;
	char *name = NULL;
	char *provider = NULL;
	Server *server = NULL;
	int ret = 0;

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
		opt_provider = 'p'
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
		{ "provider", required_argument, NULL, opt_provider },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit server <token> ..." },
		{ opt_foreground, "run the server in foreground" },
		{ opt_user, "specify user who can connect to the socket" },
		{ opt_group, "specify group who can connect to the socket" },
		{ opt_run_as_user, "specify user who runs the server" },
		{ opt_run_as_group, "specify group who runs the server" },
		{ opt_timeout, "exit if no connection until the given timeout" },
		{ opt_name, "specify name of the socket (default: pkcs11-<pid>)" },
		{ opt_provider, "specify the module to use" },
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
		case opt_provider:
			provider = optarg;
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

	if (argc < 1) {
		p11_tool_usage (usages, options);
		return 2;
	}

	if (run_as_gid != -1) {
		if (setgid (run_as_gid) == -1) {
			p11_message_err (errno, "cannot set gid to %u", (unsigned)run_as_gid);
			ret = 1;
			goto out;
		}

		if (setgroups (1, &run_as_gid) == -1) {
			p11_message_err (errno, "cannot setgroups to %u", (unsigned)run_as_gid);
			ret = 1;
			goto out;
		}
	}

	if (run_as_uid != -1) {
		if (setuid (run_as_uid) == -1) {
			p11_message_err (errno, "cannot set uid to %u", (unsigned)run_as_uid);
			ret = 1;
			goto out;
		}
	}

	if (name == NULL) {
		const char *runtime_dir;

		if (asprintf (&name, "pkcs11-%d", getpid ()) < 0) {
			ret = 1;
			goto out;
		}

		runtime_dir = secure_getenv ("XDG_RUNTIME_DIR");
		if (!runtime_dir || !runtime_dir[0]) {
			p11_message_err (errno, "cannot determine runtime directory");
			ret = 1;
			goto out;
		}

		socket_base = p11_path_build (runtime_dir, "p11-kit", NULL);
		if (socket_base == NULL) {
			ret = 1;
			goto out;
		}

		if (mkdir (socket_base, 0700) == -1 && errno != EEXIST) {
			p11_message_err (errno, "cannot create %s", socket_base);
			ret = 1;
			goto out;
		}

		socket_name = p11_path_build (socket_base, name, NULL);
		free (name);
	} else {
		socket_name = strdup (name);
	}

	server = server_new ((const char **)argv, argc, provider, socket_name);
	if (server == NULL) {
		ret = 1;
		goto out;
	}

	server->uid = uid;
	server->gid = gid;
	ret = server_loop (server, foreground, timeout);

 out:
	server_free (server);

	if (socket_name)
		free (socket_name);
	if (socket_base) {
		remove (socket_base);
		free (socket_base);
	}

	return ret;
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

#include <aclapi.h>
#include <io.h>
#include <process.h>
#include <windows.h>

#define DYN_ADVAPI32

typedef DWORD   (WINAPI *GetSecurityInfoFunc)
                                  (HANDLE handle,
                                   SE_OBJECT_TYPE ObjectType,
                                   SECURITY_INFORMATION SecurityInfo,
                                   PSID *ppsidOwner,
                                   PSID *ppsidGroup,
                                   PACL *ppDacl,
                                   PACL *ppSacl,
                                   PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
typedef DWORD   (WINAPI *SetSecurityInfoFunc)
                                  (HANDLE handle,
                                   SE_OBJECT_TYPE ObjectType,
                                   SECURITY_INFORMATION SecurityInfo,
                                   PSID psidOwner,
                                   PSID psidGroup,
                                   PACL pDacl,
                                   PACL pSacl);
typedef WINBOOL (WINAPI *OpenProcessTokenFunc)
                                  (HANDLE ProcessHandle,
                                   DWORD DesiredAccess,
                                   PHANDLE TokenHandle);
typedef WINBOOL (WINAPI *GetTokenInformationFunc)
                                  (HANDLE TokenHandle,
                                   TOKEN_INFORMATION_CLASS TokenInformationClass,
                                   LPVOID TokenInformation,
                                   DWORD TokenInformationLength,
                                   PDWORD ReturnLength);
typedef WINBOOL (WINAPI *InitializeSecurityDescriptorFunc)
                                  (PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                   DWORD dwRevision);
typedef WINBOOL (WINAPI *SetSecurityDescriptorOwnerFunc)
                                  (PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                   PSID pOwner,
                                   WINBOOL bOwnerDefaulted);
typedef DWORD   (WINAPI *SetEntriesInAclAFunc)
                                  (ULONG cCountOfExplicitEntries,
                                   PEXPLICIT_ACCESS_A pListOfExplicitEntries,
                                   PACL OldAcl,
                                   PACL *NewAcl);

#ifdef DYN_ADVAPI32
static GetSecurityInfoFunc pGetSecurityInfo;
static SetSecurityInfoFunc pSetSecurityInfo;
static OpenProcessTokenFunc pOpenProcessToken;
static GetTokenInformationFunc pGetTokenInformation;
static InitializeSecurityDescriptorFunc pInitializeSecurityDescriptor;
static SetSecurityDescriptorOwnerFunc pSetSecurityDescriptorOwner;
static SetEntriesInAclAFunc pSetEntriesInAclA;
#else
#define pGetSecurityInfo GetSecurityInfo
#define pSetSecurityInfo SetSecurityInfo
#define pOpenProcessToken OpenProcessToken
#define pGetTokenInformation GetTokenInformation
#define pInitializeSecurityDescriptor InitializeSecurityDescriptor
#define pSetSecurityDescriptorOwner SetSecurityDescriptorOwner
#define pSetEntriesInAclA SetEntriesInAclA
#endif

#define BUFSIZE 4096

static bool quiet = false;

struct ThreadData {
	HANDLE handle;
	Server *server;
};

static DWORD WINAPI
server_thread (LPVOID lpvParam)
{
	struct ThreadData *data = lpvParam;
	Server *server = data->server;
	int fd;

	fd = _open_osfhandle ((intptr_t) data->handle, _O_BINARY);
	if (fd < 0) {
		free (data);
		return 1;
	}

	if (server->module != NULL && server->provider == NULL) {
		p11_kit_remote_serve_module (server->module, fd, fd);
	} else {
		p11_kit_remote_serve_tokens ((const char **)server->tokens,
					     server->n_tokens,
					     server->module,
					     fd, fd);
	}

	free (data);
	_close (fd);
	return 1;
}

static bool
make_private_security_descriptor (DWORD permissions,
				  PSECURITY_DESCRIPTOR *psd,
				  PACL *acl);

static int
server_loop (Server *server)
{
	HANDLE hpipe, hthread;
	BOOL connected = FALSE;
	DWORD thread_id = 0;
	SECURITY_ATTRIBUTES sa;
	PACL acl;
	struct ThreadData *data;

	memset (&sa, 0, sizeof (SECURITY_ATTRIBUTES));
	sa.nLength = sizeof (sa);
	sa.bInheritHandle = FALSE;

	if (!make_private_security_descriptor (GENERIC_READ | GENERIC_WRITE,
					       &sa.lpSecurityDescriptor,
					       &acl))
		return 1;

	if (!quiet) {
		char *path;

		path = p11_path_encode (server->socket_name);
		printf ("P11_KIT_SERVER_ADDRESS=windows:pipe=%s\n", path);
		free (path);
		printf ("P11_KIT_SERVER_PID=%d\n", getpid ());
	}

	while (1) {
		hpipe = CreateNamedPipe (server->socket_name,
					 PIPE_ACCESS_DUPLEX,
					 PIPE_TYPE_BYTE |
					 PIPE_READMODE_BYTE |
					 PIPE_WAIT
#ifdef PIPE_REJECT_REMOTE_CLIENTS
					 | PIPE_REJECT_REMOTE_CLIENTS
#endif
					 ,
					 PIPE_UNLIMITED_INSTANCES,
					 BUFSIZE,
					 BUFSIZE,
					 0,
					 &sa);
		if (hpipe == INVALID_HANDLE_VALUE)
			return 1;
		connected = ConnectNamedPipe (hpipe, NULL);
		if (!connected)
			connected = GetLastError () == ERROR_PIPE_CONNECTED;
		if (connected) {
			data = malloc (sizeof (struct ThreadData));
			data->handle = hpipe;
			data->server = server;
			hthread = CreateThread (NULL, 0, server_thread, data, 0,
						&thread_id);
			if (hthread == NULL) {
				free (data);
				return 1;
			} else
				CloseHandle(hthread);
		} else {
			CloseHandle(hpipe);
		}
	}

	return 0;
}

static HMODULE advapi32_lib;

static bool
load_windows_functions (void)
{
	advapi32_lib = LoadLibraryA ("advapi32.dll");
	return_val_if_fail (advapi32_lib != NULL, false);

#define GET_WINDOWS_FUNCTION(func) \
	p ## func = (func ## Func) GetProcAddress (advapi32_lib, # func); \
	return_val_if_fail (p ## func != NULL, false)

	GET_WINDOWS_FUNCTION (GetSecurityInfo);
	GET_WINDOWS_FUNCTION (SetSecurityInfo);
	GET_WINDOWS_FUNCTION (OpenProcessToken);
	GET_WINDOWS_FUNCTION (GetTokenInformation);
	GET_WINDOWS_FUNCTION (InitializeSecurityDescriptor);
	GET_WINDOWS_FUNCTION (SetSecurityDescriptorOwner);
	GET_WINDOWS_FUNCTION (SetEntriesInAclA);

	return true;
}

int
main (int argc,
      char *argv[])
{
	const char *pipe_base = "\\\\.\\pipe\\";
	char *pipe_name;
	int opt;
	const char *name = NULL;
	char *provider = NULL;
	Server *server = NULL;
	int ret = 0;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_name = 'n',
		opt_provider = 'p'
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "name", required_argument, NULL, opt_name },
		{ "provider", required_argument, NULL, opt_provider },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit server <token> ..." },
		{ opt_name, "specify name of the pipe (default: pkcs11-<pid>)" },
		{ opt_provider, "specify the module to use" },
		{ 0 },
	};

	if (!load_windows_functions ()) {
		p11_message ("couldn't initialize Windows security functions");
		return 1;
	}

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_quiet:
			quiet = true;
			break;
		case opt_name:
			name = optarg;
			break;
		case opt_provider:
			provider = optarg;
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

	if (argc < 1) {
		p11_tool_usage (usages, options);
		return 2;
	}

	if (name == NULL) {
		if (asprintf (&pipe_name, "%spkcs11-%d",
			      pipe_base, _getpid ()) < 0) {
			ret = 1;
			goto out;
		}
	} else {
		pipe_name = strdup (name);
	}

	server = server_new ((const char **)argv, argc, provider, pipe_name);
	if (server == NULL) {
		ret = 1;
		goto out;
	}

	ret = server_loop (server);

 out:
	server_free (server);

	if (pipe_name)
		free (pipe_name);

	if (advapi32_lib)
		FreeLibrary (advapi32_lib);

	return ret;
}

/* make_private_security_descriptor() and the helper functions were
 * copied from putty/windows/winsecur.c in the PuTTY source code as of
 * git commit 12bd5a6c722152aa27f24598785593e72b3284ea.
 *
 * PuTTY is copyright 1997-2017 Simon Tatham.
 *
 * Portions copyright Robert de Bath, Joris van Rantwijk, Delian
 * Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry,
 * Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus
 * Kuhn, Colin Watson, Christopher Staite, and CORE SDI S.A.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* Initialised once, then kept around to reuse forever */
static PSID world_sid, network_sid, user_sid;

static PSID
get_user_sid (void)
{
	HANDLE proc = NULL, tok = NULL;
	TOKEN_USER *user = NULL;
	DWORD toklen, sidlen;
	PSID sid = NULL, ret = NULL;

	if (user_sid)
		return user_sid;

	if ((proc = OpenProcess (MAXIMUM_ALLOWED, FALSE,
				 GetCurrentProcessId ())) == NULL)
		goto cleanup;

	if (!OpenProcessToken (proc, TOKEN_QUERY, &tok))
		goto cleanup;

	if (!GetTokenInformation (tok, TokenUser, NULL, 0, &toklen) &&
	    GetLastError () != ERROR_INSUFFICIENT_BUFFER)
		goto cleanup;

	if ((user = (TOKEN_USER *)LocalAlloc (LPTR, toklen)) == NULL)
		goto cleanup;

	if (!GetTokenInformation (tok, TokenUser, user, toklen, &toklen))
		goto cleanup;

	sidlen = GetLengthSid (user->User.Sid);

	sid = (PSID)malloc (sidlen);

	if (!CopySid (sidlen, sid, user->User.Sid))
		goto cleanup;

	/* Success. Move sid into the return value slot, and null it out
	 * to stop the cleanup code freeing it. */
	ret = user_sid = sid;
	sid = NULL;

 cleanup:
	if (proc != NULL)
		CloseHandle (proc);
	if (tok != NULL)
		CloseHandle (tok);
	if (user != NULL)
		LocalFree (user);
	if (sid != NULL)
		free (sid);

	return ret;
}

static bool
get_sids (void)
{
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif
	SID_IDENTIFIER_AUTHORITY world_auth = { SECURITY_WORLD_SID_AUTHORITY };
	SID_IDENTIFIER_AUTHORITY nt_auth = { SECURITY_NT_AUTHORITY };
#ifdef __clang__
#pragma clang diagnostic pop
#endif

	if (!user_sid) {
		user_sid = get_user_sid ();
		if (user_sid == NULL) {
			p11_message ("unable to construct SID for %s: %lu",
				     "current user",
				     GetLastError ());
			return false;
		}
	}

	if (!world_sid) {
		if (!AllocateAndInitializeSid (&world_auth, 1,
					       SECURITY_WORLD_RID,
					       0, 0, 0, 0, 0, 0, 0,
					       &world_sid)) {
			p11_message ("unable to construct SID for %s: %lu",
				     "world",
				     GetLastError ());
			return false;
		}
	}

	if (!network_sid) {
		if (!AllocateAndInitializeSid (&nt_auth, 1,
					       SECURITY_NETWORK_RID,
					       0, 0, 0, 0, 0, 0, 0,
					       &network_sid)) {
			p11_message ("unable to construct SID for %s: %lu",
				     "local same-user access only",
				     GetLastError ());
			return false;
		}
	}

	return true;
}

static bool
make_private_security_descriptor (DWORD permissions,
				  PSECURITY_DESCRIPTOR *psd,
				  PACL *acl)
{
	EXPLICIT_ACCESS ea[3];
	int acl_err;

	*psd = NULL;
	*acl = NULL;

	if (!get_sids ())
		goto cleanup;

	memset (ea, 0, sizeof(ea));
	ea[0].grfAccessPermissions = permissions;
	ea[0].grfAccessMode = REVOKE_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.ptstrName = (LPTSTR)world_sid;
	ea[1].grfAccessPermissions = permissions;
	ea[1].grfAccessMode = GRANT_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.ptstrName = (LPTSTR)user_sid;
	ea[2].grfAccessPermissions = permissions;
	ea[2].grfAccessMode = REVOKE_ACCESS;
	ea[2].grfInheritance = NO_INHERITANCE;
	ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[2].Trustee.ptstrName = (LPTSTR)network_sid;

	acl_err = SetEntriesInAclA (3, ea, NULL, acl);
	if (acl_err != ERROR_SUCCESS || *acl == NULL) {
		p11_message ("unable to construct ACL: %d", acl_err);
		goto cleanup;
	}

	*psd = (PSECURITY_DESCRIPTOR) LocalAlloc (LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!*psd) {
		p11_message ("unable to allocate security descriptor: %lu",
			     GetLastError ());
		goto cleanup;
	}

	if (!InitializeSecurityDescriptor (*psd, SECURITY_DESCRIPTOR_REVISION)) {
		p11_message ("unable to initialise security descriptor: %lu",
			     GetLastError ());
		goto cleanup;
	}

	if (!SetSecurityDescriptorOwner (*psd, user_sid, FALSE)) {
		p11_message ("unable to set owner in security descriptor: %lu",
			     GetLastError ());
		goto cleanup;
	}

	if (!SetSecurityDescriptorDacl (*psd, TRUE, *acl, FALSE)) {
		p11_message ("unable to set DACL in security descriptor: %lu",
			     GetLastError ());
		goto cleanup;
	}

	return true;

 cleanup:
	if (*psd) {
		LocalFree (*psd);
		*psd = NULL;
	}
	if (*acl) {
		LocalFree (*acl);
		*acl = NULL;
	}

	return false;
}

#endif /* OS_WIN32 */
