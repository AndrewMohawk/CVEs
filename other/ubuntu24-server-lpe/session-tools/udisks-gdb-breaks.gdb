set pagination off
set confirm off
set breakpoint pending on
set print thread-events off
set detach-on-fork on
set follow-fork-mode parent
handle SIGPIPE nostop noprint pass

break g_dbus_method_invocation_return_dbus_error
commands
silent
printf "HIT return_dbus_error inv=%p error=%s message=%s\n", $x0, (char *) $x1, (char *) $x2
bt 8
continue
end

break g_dbus_method_invocation_get_sender
commands
silent
printf "HIT get_sender inv=%p\n", $x0
bt 8
continue
end

break udisks_daemon_util_check_authorization_sync
commands
silent
printf "HIT auth_sync action=%s invocation=%p\n", (char *) $x2, $x5
bt 8
continue
end

break udisks_daemon_util_check_authorization_sync_with_error
commands
silent
printf "HIT auth_with_error action=%s invocation=%p\n", (char *) $x2, $x5
bt 8
continue
end

break bd_fs_check
commands
silent
printf "HIT bd_fs_check device=%s type=%s\n", (char *) $x0, (char *) $x1
bt 10
continue
end

break bd_fs_repair
commands
silent
printf "HIT bd_fs_repair device=%s type=%s\n", (char *) $x0, (char *) $x1
bt 10
continue
end

break bd_fs_resize
commands
silent
printf "HIT bd_fs_resize device=%s size=%llu type=%s\n", (char *) $x0, (unsigned long long) $x1, (char *) $x2
bt 10
continue
end

continue
