#include <stdio.h>
#include <stdlib.h>
#include <dbus/dbus.h>
#include <libnotify/notify.h>

static void allow_callback(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    // Use pkexec with a custom PolicyKit action (recommended)
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> /etc/xsm/whitelist'", proc);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to whitelist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to whitelist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void deny_callback(NotifyNotification *notification,
                          const char *action,
                          gpointer user_data)
{
    printf("User chose Deny for whitelist addition.\n");
    notify_notification_close(notification, NULL);
}

void display_notification(const char *process_name, const char *title, const char *body)
{
    notify_init("XSM-Agent");

    NotifyNotification *n = notify_notification_new(title, body, "dialog-warning");
    notify_notification_set_timeout(n, 15000);   // 15 seconds

    if (process_name && process_name[0] != '\0') {
        notify_notification_add_action(n,
            "allow", "Allow",
            (NotifyActionCallback)allow_callback,
            g_strdup(process_name),      // pass clean process name
            (GFreeFunc)g_free);

        notify_notification_add_action(n,
            "deny", "Deny",
            (NotifyActionCallback)deny_callback,
            NULL, NULL);
    }

    notify_notification_show(n, NULL);
}

int main() {
    DBusConnection *conn;
    DBusError err;

    dbus_error_init(&err);

    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Connection Error: %s\n", err.message);
        dbus_error_free(&err);
        return 1;
    }

    dbus_bus_add_match(conn, "type='signal',interface='org.xsm.SecurityInterface'", &err);
    dbus_connection_flush(conn);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Match Error: %s\n", err.message);
        return 1;
    }

    printf("XSM Agent listening for security signals...\n");

    while (1) {
        while (g_main_context_iteration(NULL, FALSE));

        dbus_connection_read_write(conn, 0);
        DBusMessage *msg = dbus_connection_pop_message(conn);

        if (msg == NULL) {
            continue;
        }

        // Check if the message is our specific signal
        if (dbus_message_is_signal(msg, "org.xsm.SecurityInterface", "ViolationDetected")) {
            char *process_name = NULL;
            char *full_message  = NULL;

            if (dbus_message_get_args(msg, &err,
                                      DBUS_TYPE_STRING, &process_name,
                                      DBUS_TYPE_STRING, &full_message,
                                      DBUS_TYPE_INVALID)) {

                printf("Security violation received - Process: '%s' | Message: %s\n",
                       process_name ? process_name : "(null)",
                       full_message ? full_message : "(null)");

                display_notification(process_name, full_message, "");
            } else {
                fprintf(stderr, "Failed to parse D-Bus signal arguments\n");
            }
        }
        dbus_message_unref(msg);
    }

    return 0;
}
