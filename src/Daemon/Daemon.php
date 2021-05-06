<?php

/*******************************************************************************
*                                                                              *
*   Daemon.php                                                                 *
*                                                                              *
*   Enables PHP programs to correctly daemonize themselves in most Unix-like   *
*   operating systems.
*                                                                              *
*   LICENSE                                                                    *
*                                                                              *
*   Copyright (c) 2021 Rob Sheldon <rob@robsheldon.com>                        *
*                                                                              *
*   Permission is hereby granted, free of charge, to any person obtaining a    *
*   copy of this software and associated documentation files (the "Software"), *
*   to deal in the Software without restriction, including without limitation  *
*   the rights to use, copy, modify, merge, publish, distribute, sublicense,   *
*   and/or sell copies of the Software, and to permit persons to whom the      *
*   Software is furnished to do so, subject to the following conditions:       *
*                                                                              *
*   The above copyright notice and this permission notice shall be included    *
*   in all copies or substantial portions of the Software.                     *
*                                                                              *
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    *
*   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                 *
*   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.     *
*   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY       *
*   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,       *
*   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE          *
*   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                     *
*                                                                              *
*   https://opensource.org/licenses/MIT                                        *
*                                                                              *
*******************************************************************************/

/*******************************************************************************
*                                                                              *
*   Notes                                                                      *
*                                                                              *
*   References:                                                                *
*   https://stackoverflow.com/questions/2036654/run-php-script-as-daemon-process
*   https://stackoverflow.com/questions/17954432/creating-a-daemon-in-linux    *
*   https://php.net/manual/en/function.posix-setsid.php                        *
*   https://kvz.io/blog/2009/01/09/create-daemons-in-php/                      *
*   http://www.re-cycledair.com/php-dark-arts-daemonizing-a-process            *
*   https://web.archive.org/web/20130801043257/http://www.thudgame.com/node/254
*        ^ some good ideas here, like periodically touching the PID file.      *
*   https://us2.php.net/manual/en/function.pcntl-signal.php                    *
*        ^  use pcntl_signal_dispatch instead of ticks                         *
*   https://secure.php.net/manual/en/pcntl.constants.php                       *
*   https://php.net/manual/en/function.syslog.php                              *
*   https://php.net/manual/en/function.socket-accept.php                       *
*        ^  see notes at bottom for creating a daemon socket server.           *
*                                                                              *
*******************************************************************************/

namespace Asinius\Daemon;


/*******************************************************************************
*                                                                              *
*   Runtime checks.                                                            *
*                                                                              *
*******************************************************************************/

if ( ! function_exists('pcntl_fork') ) {
    throw new \RuntimeException('pcntl_* functions may not be installed in this environment. See also https://secure.php.net/manual/en/pcntl.installation.php', ENOSYS);
}

if (   ! function_exists('posix_getpwuid') 
    || ! function_exists('posix_geteuid')
    || ! function_exists('posix_getpwnam')
    || ! function_exists('posix_setuid')
    || ! function_exists('posix_setgid')
    || ! function_exists('posix_setsid')
    || ! function_exists('posix_getpid')
) {
    throw new \RuntimeException('posix_* functions may not be installed in this environment. See also https://secure.php.net/manual/en/posix.installation.php', ENOSYS);
}


/*******************************************************************************
*                                                                              *
*   \Asinius\Daemon\Daemon                                                     *
*                                                                              *
*******************************************************************************/

class Daemon
{
    private static $_instances          = array();
    private static $_callback           = null;
    private static $_interval_usecs     = 0;
    private static $_name               = '';
    private static $_piddir             = '';
    private static $_pidfile            = '';
    private static $_uid                = null;
    private static $_gid                = 1;
    private static $_pid                = 0;
    private static $_syslog             = null;
    private static $_options            = null;
    private static $_last_heartbeat     = 0;
    private static $_signal_handlers    = array();


    /**
     * Internal function that daemonizes the current application.
     *
     * @internal
     *
     * @throws  RuntimeException
     *
     * @return  true
     */
    private static function _daemonize ()
    {
        //  Daemonize the current application:
        //      Create a child process;
        //      Detach it from the current process;
        //      Get the init process to adopt it;
        //      Do necessary cleanup;
        //      Detach from the terminal.
        if ( self::$_options['require_root'] === true ) {
            //  Make sure the current user is root, otherwise refuse to daemonize.
            $user_info = posix_getpwuid(posix_geteuid());
            if ( strtolower($user_info['name']) != 'root' || $user_info['uid'] != 0 ) {
                throw new \RuntimeException('Must be root to daemonize this application', EPERM);
            }
        }
        //  Make sure there isn't already a PID file for this daemon.
        self::$_piddir = '/var/run/' . self::$_name;
        self::$_pidfile = self::$_piddir . '/run.pid';
        if ( @file_exists(self::$_pidfile) ) {
            throw new \RuntimeException('Another instance may already be running; there is a PID file at ' . self::$_pidfile, EALREADY);
        }
        //  Now make sure we have a valid UID to run as.
        if ( is_integer(self::$_options['run_as']) ) {
            self::$_uid = self::$_options['run_as'];
        }
        else if ( is_string(self::$_options['run_as']) ) {
            $user_info = posix_getpwnam(self::$_options['run_as']);
            if ( $user_info === false ) {
                throw new \RuntimeException('User "' . self::$_options['run_as'] . '" was not found on this system', EINVAL);
            }
            self::$_uid = $user_info['uid'];
        }
        $user_info = posix_getpwuid(self::$_uid);
        if ( $user_info === false ) {
            throw new \RuntimeException('UID ' . self::$_uid . ' was not found on this system', EINVAL);
        }
        self::$_gid = $user_info['gid'];
        //  The PID file needs to be written before privileges are dropped.
        //  Create the PID file that will be used later and chown/chgrp it to
        //  the uid/gid to be used. This has to be done before privileges are
        //  are dropped because the "daemon" and "nobody" (and other) users
        //  don't have write access to /var/run.
        //  But before the PID file is written, the default file permissions
        //  need to be changed to only rw for the owning user.
        umask(0077);
        if ( ! @file_exists(self::$_piddir) ) {
            if ( ! @mkdir(self::$_piddir) ) {
                throw new \RuntimeException('Could not create PID directory at ' . self::$_piddir, EACCESS);
            }
        }
        if ( ! is_dir(self::$_piddir) ) {
            throw new \RuntimeException(self::$_piddir . ' exists but is not a directory', EEXIST);
        }
        if ( fileowner(self::$_piddir) != self::$_uid ) {
            if ( ! chown(self::$_piddir, self::$_uid) ) {
                throw new \RuntimeException('Could not change ownership of ' . self::$_piddir . ' to uid ' . self::$_uid, EACCESS);
            }
        }
        if ( filegroup(self::$_piddir) != self::$_gid ) {
            if ( ! chgrp(self::$_piddir, self::$_gid) ) {
                throw new \RuntimeException('Could not change group ownership of ' . self::$_piddir . ' to gid ' . self::$_gid, EACCESS);
            }
        }
        if ( ! touch(self::$_pidfile) ) {
            throw new \RuntimeException('Could not create or modify PID file at ' . self::$_pidfile, EACCESS);
        }
        if ( ! chown(self::$_pidfile, self::$_uid) ) {
            throw new \RuntimeException('Failed to change ownership of PID file at ' . self::$_pidfile . ' to UID ' . self::$_uid, EACCESS);
        }
        if ( ! chgrp(self::$_pidfile, self::$_gid) ) {
            throw new \RuntimeException('Failed to change group ownership of PID file at ' . self::$_pidfile . ' to GID ' . self::$_gid, EACCESS);
        }
        //  Now try to switch to the provided uid/gid.
        //  GID switch has to be done first.
        if ( ! posix_setgid(self::$_gid) ) {
            throw new \RuntimeException('Could not switch to GID ' . self::$_gid, EPERM);
        }
        if ( ! posix_setuid(self::$_uid) ) {
            throw new \RuntimeException('Could not switch to UID ' . self::$_uid, EPERM);
        }
        if ( self::$_options['drop_privs'] != false ) {
            //  Now make sure it's impossible to get root privileges back.
            if ( posix_setuid(0) ) {
                throw new \RuntimeException('Failed to drop root privileges', EPERM);
            }
        }
        //  Make sure the pid file can be written to by this user.
        if ( ! is_writable(self::$_pidfile) ) {
            throw new \RuntimeException("Can't write to my PID file at " . self::$_pidfile . ' as user ' . self::$_uid, EPERM);
        }
        if ( is_string(self::$_options['chroot_to']) ) {
            //  Make sure this user has access to the chroot directory.
            if ( ! @file_exists(self::$_options['chroot_to']) ) {
                throw new \RuntimeException("Can't chroot: " . self::$_options['chroot_to'] . " doesn't exist", ENOENT);
            }
            if ( ! is_dir(self::$_options['chroot_to']) ) {
                throw new \RuntimeException("Can't chroot: " . self::$_options['chroot_to'] . ' is not a directory', ENOTDIR);
            }
            if ( ! is_readable(self::$_options['chroot_to']) ) {
                throw new \RuntimeException("Can't chroot: " . self::$_options['chroot_to'] . ' is not readable', EACCESS);
            }
        }
        //  All pre-flight checks are complete. Now fork() for the first time
        //  and kill the parent process so that the init process (pid 1) will
        //  grab this process and control will return to the terminal.
        ob_implicit_flush(true);
        flush();
        $pid = pcntl_fork();
        if ( $pid === -1 ) {
            //  TODO: to be more robust, this should remove the PID file and
            //      set some other conditions to try again.
            //      This is for now being thrown as an error.
            //  fork() might fail due to some temporary resource limitation.
            throw new \RuntimeException('Failed to fork()', EAGAIN);
        }
        else if ( $pid !== 0 ) {
            //  Kill the parent process.
            exit();
        }
        //  posix_setsid() causes this process to detach from the user's
        //  terminal so that it will continue running even if the terminal
        //  session is closed.
        if ( posix_setsid() < 0 ) {
            throw new \RuntimeException('posix_setsid() failed', EUNDEF);
        }
        //  fork() one more time, for reasons I don't entirely understand, but
        //  are considered good practices anyway. posix_setsid() detaches the
        //  current process from its TTY, but apparently makes it a session
        //  leader which can theoretically reattach to a TTY.
        //  fork()ing again prevents the possibility of reattaching to a terminal.
        $pid = pcntl_fork();
        if ( $pid === -1 ) {
            throw new \RuntimeException('Secondary fork() after posix_setsid() failed', EAGAIN);
        }
        if ( $pid !== 0 ) {
            //  Kill this process too.
            exit();
        }
        //  Open a connection to syslog, if enabled.
        if ( self::$_options['enable_syslog'] === true ) {
            self::$_syslog = openlog(self::$_name, LOG_NDELAY | LOG_PID, LOG_DAEMON);
        }
        if ( is_string(self::$_options['chroot_to']) ) {
            //  chroot() now to help prevent possible compromises of the daemon
            //  process from getting full access to the server filesystem --
            //  assuming of course the application chose a sane root dir.
            if ( ! @chroot(self::$_options['chroot_to']) ) {
                throw new \RuntimeException('Could not chroot to ' . self::$_options['chroot_to'], EUNDEF);
            }
        }
        //  umask(0022) to prevent group/others from writing any files created
        //  by the daemonized process.
        umask(22);
        //  Close STDIN, STDOUT, STDERR filehandles.
        //  If any of these fails, ignore it.
        @fclose(STDIN);
        @fclose(STDOUT);
        @fclose(STDERR);
        //  Get our PID. The _poll() function will update the PID file.
        self::$_pid = posix_getpid();
        //  Set up signal handlers for all signals.
        //  https://secure.php.net/manual/en/pcntl.constants.php
        pcntl_signal(SIGINT, array(get_called_class(), 'signal_handler'));
        pcntl_signal(SIGTERM, array(get_called_class(), 'signal_handler'));
        pcntl_signal(SIGHUP, array(get_called_class(), 'signal_handler'));
        //  Success! Tell the user.
        self::log(LOG_NOTICE, 'started');
        return true;
    }


    /**
     * Initializes a new daemon static object.
     *
     * @param   string      $name
     * @param   callable    $callback
     * @param   integer     $interval
     * @param   mixed       $options
     *
     * @throws  \TypeError
     * @throws  \RuntimeException
     *
     * @return  \Asinius\Daemon\Daemon
     */
    protected function __construct ($name, $callback, $interval, $options = null) {
        //  $name: a short name for your daemon. This is for the /var/run PID
        //      file and for logging purposes.
        //  $callback: a callback function to be run every $interval milliseconds.
        //  $options: optional parameters:
        //      'run_as': the name or integer UID of a system account to run as.
        //          Recommended: 'daemon', 'nobody'. Avoid running the daemon
        //          as root.
        //      'chroot_to': directory to chroot() to while daemonizing.
        //      'enable_syslog': whether or not to write messages to syslog.
        //      'require_root': whether the parent application must be running
        //          as root to daemonize.
        if ( ! empty(self::$_instances[get_called_class()]['inited']) && self::$_instances[get_called_class()]['inited'] ) {
            throw new \RuntimeException('A static instance of ' . get_called_class() . ' has already been instantiated', -1);
            return;
        }
        if ( empty($name) || ! is_string($name) || preg_match('/^[A-Za-z0-9_-]+$/', $name) !== 1 ) {
            throw new \RuntimeException('Invalid daemon $name', EINVAL);
        }
        if ( empty($callback) || ! is_callable($callback) ) {
            throw new TypeError('Invalid argument for $callback', EINVAL);
        }
        if ( empty($interval) || ! is_integer($interval) || $interval < 1 ) {
            throw new TypeError('Invalid argument for $interval', EINVAL);
        }
        self::$_name = $name;
        self::$_callback = $callback;
        //  Convert $interval (milliseconds) to microseconds.
        self::$_interval_usecs = $interval * 1000;
        self::$_options = array(
            'run_as'        => 'daemon',
            'chroot_to'     => null,
            'enable_syslog' => false,
            'require_root'  => true,
            'drop_privs'    => true,
        );
        if ( is_array($options) && ! empty($options) ) {
            self::$_options = array_merge(self::$_options, $options);
        }
        self::$_instances[get_called_class()]['inited'] = true;
    }


    /**
     * Clean up on exit.
     *
     * @return  void
     */
    public function __destruct ()
    {
        //  Don't do cleanup if this object was in one of the parent processes.
        if ( self::$_pid !== 0 ) {
            self::log(LOG_NOTICE, 'exiting');
            //  Remove the pid file, if one exists and is writable.
            if ( ! empty(self::$_pidfile) && @file_exists(self::$_pidfile) && is_writable(self::$_pidfile) ) {
                unlink(self::$_pidfile);
            }
            //  Close our connection to syslog, if one exists.
            if ( ! is_null(self::$_syslog) ) {
                closelog();
            }
        }
    }


    /**
     * Call the application's callback function on a millisecond interval
     * until exit.
     *
     * @internal
     *
     * @return  void
     */
    private static function _poll ()
    {
        while ( true ) {
            $start = gettimeofday(false);
            //  Call the application's callback function.
            call_user_func(self::$_callback);
            //  Do some housekeeping.
            //  Dispatch any pending signals.
            pcntl_signal_dispatch();
            //  Rewrite the PID file every few minutes as an indicator that the
            //  process isn't stuck.
            if ( time() - self::$_last_heartbeat > 60 * 5 ) {
                //  Set the last heartbeat now to prevent wrecking filesystem
                //  i/o if there's some problem writing the PID file.
                self::$_last_heartbeat = time();
                if ( @file_put_contents(self::$_pidfile, sprintf('%d', posix_getpid())) === false ) {
                    throw new \RuntimeException('Failed to write to PID file at ' . self::$_pidfile, EUNDEF);
                }
            }
            //  Calculate sleep time in microseconds and then adjust for nanoseconds.
            //  There are a few tradeoffs here: doing it this way isn't
            //  perfectly accurate, but more precision would be slower.
            $now = gettimeofday(false);
            //  Sleep time = interval - elapsed (microseconds)
            $sleep_usecs = self::$_interval_usecs - (($now['sec'] - $start['sec']) * 1000000 + $now['usec'] - $start['usec']);
            if ( $sleep_usecs > 0 ) {
                $microseconds = $sleep_usecs % 1000000;
                time_nanosleep(($sleep_usecs - $microseconds) / 1000000, $microseconds * 1000);
            }
        }
        exit();
    }


    /**
     * Handle signals sent by the operating system.
     *
     * This is an internal function but must be defined as a public function;
     * private functions can't be used as callables outside the object scope
     * per PHP docs.
     *
     * @internal
     *
     * @param   integer     $signal_number
     * @param   mixed       $signal_info
     *
     * @return  void
     */
    public static function signal_handler ($signal_number, $signal_info = null)
    {
        switch ($signal_number) {
            case SIGTERM:
                //  Unceremoniously halt. It's expected that the application
                //  will use destructors or register_shutdown_function()
                //  for cleanup as necessary.
                exit();
            default:
                //  See if the application has registered a callback function
                //  for this signal. If not, ignore it?
                if ( array_key_exists($signal_number, self::$_signal_handlers) ) {
                    self::$_signal_handlers[$signal_number]($signal_number, $signal_info);
                }
        }
    }


    /**
     * Daemonize the current application. This function does not return; if
     * daemonizing is successful, then the daemon begins calling the
     * application's main loop every $interval milliseconds.
     *
     * @param   string      $name
     * @param   callable    $callback
     * @param   integer     $interval
     * @param   mixed       $options
     *
     * @throws  TypeError
     * @throws  RuntimeException
     *
     * @return  void
     */
    public static function daemonize ($name, $callback, $interval, $options = null)
    {
        //  Make sure the parent process has finished all output, closed all filehandles, and
        //      is ready to exit() before calling daemonize(). daemonize() will unceremoniously
        //      kill the parent script.
        //  get_called_class() requires PHP >= 5.3, for late static binding.
        $classname = get_called_class();
        if ( empty(self::$_instances[$classname]['inited']) ) {
            //  Set an uninitialized flag for this instance.
            //  The flag only gets set by the instance after successfully
            //  initing.
            self::$_instances[$classname] = array('instance' => null, 'inited' => false);
            self::$_instances[$classname]['instance'] = new static($name, $callback, $interval, $options);
            if ( self::$_instances[$classname]['inited'] && self::_daemonize() ) {
                //  Go into main daemon loop.
                self::_poll();
            }
        }
    }


    /**
     * Log a message to syslog.
     *
     * @param   integer     $priority
     * @param   string      $message
     *
     * @return  void
     */
    public static function log ($priority, $message)
    {
        //  TODO: support other logging mechanisms.
        if ( ! is_null(self::$_syslog) ) {
            syslog($priority, $message);
        }
    }


    /**
     * Enable logging to syslog.
     *
     * @return  void
     */
    public function enable_syslog ()
    {
        if ( self::$_options['enable_syslog'] === false ) {
            if ( is_null(self::$_syslog) ) {
                self::$_syslog = openlog(self::$_name, LOG_NDELAY | LOG_PID, LOG_DAEMON);
            }
            self::$_options['enable_syslog'] = true;
        }
    }


    /**
     * Disable logging to syslog.
     *
     * @return  void
     */
    public function disable_syslog ()
    {
        if ( self::$_options['enable_syslog'] === true ) {
            if ( ! is_null(self::$_syslog) ) {
                closelog();
                self::$_syslog = null;
            }
            self::$_options['enable_syslog'] = false;
        }
    }


    /**
     * Allow the application to capture specific signals.
     *
     * Note: the daemon will not return SIGTERM signals to the application;
     * for safety, it simply calls exit() if a SIGTERM is received.
     *
     * @param   integer     $signal_number
     * @param   callable    $callback
     *
     * @return  void
     */
    public function set_signal_handler ($signal_number, $callback)
    {
        self::$_signal_handlers[$signal_number] = $callback;
    }
}
