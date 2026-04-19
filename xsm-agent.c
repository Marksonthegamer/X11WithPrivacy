#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <libnotify/notify.h>

#define LOG_SCREENSHOT	0
#define LOG_SCREENCAST	1
#define LOG_XRECORD		3
#define LOG_CLIPBOARD	4

#define WHITELIST_SCREENSHOT   "/etc/xsm/whitelist_screenshot"
#define WHITELIST_SCREENCAST   "/etc/xsm/whitelist_screencast"
#define WHITELIST_XRECORD      "/etc/xsm/whitelist_xrecord"
#define WHITELIST_CLIPBOARD    "/etc/xsm/whitelist_clipboard"

#define BLACKLIST_SCREENSHOT   "/etc/xsm/blacklist_screenshot"
#define BLACKLIST_SCREENCAST   "/etc/xsm/blacklist_screencast"
#define BLACKLIST_XRECORD      "/etc/xsm/blacklist_xrecord"
#define BLACKLIST_CLIPBOARD    "/etc/xsm/blacklist_clipboard"

static void allow_callback_screenshot(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    if (snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, WHITELIST_SCREENSHOT) >= (int)sizeof(cmd)) {
        fprintf(stderr, "Command too long for buffer.\n");
    } else {
        int ret = system(cmd);
        if (ret == 0) {
            printf("Successfully added '%s' to screenshot whitelist.\n", proc);
        } else {
            fprintf(stderr, "Failed to add '%s' to screenshot whitelist (code %d)\n", proc, ret);
        }
    }

    notify_notification_close(notification, NULL);
}

static void allow_callback_screencast(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, WHITELIST_SCREENCAST);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to screencast whitelist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to screencast whitelist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void allow_callback_clipboard(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, WHITELIST_CLIPBOARD);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to clipboard whitelist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to clipboard whitelist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void allow_callback_xrecord(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, WHITELIST_XRECORD);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to xrecord whitelist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to xrecord whitelist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void deny_callback_screenshot(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, BLACKLIST_SCREENSHOT);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to screenshot blacklist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to screenshot blacklist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void deny_callback_screencast(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, BLACKLIST_SCREENCAST);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to screencast blacklist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to screencast blacklist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void deny_callback_clipboard(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, BLACKLIST_CLIPBOARD);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to clipboard blacklist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to clipboard blacklist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

static void deny_callback_xrecord(NotifyNotification *notification,
                           const char *action,
                           gpointer user_data)
{
    const char *proc = (const char *)user_data;
    if (!proc || !*proc) {
        notify_notification_close(notification, NULL);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "pkexec /bin/sh -c 'echo \"%s\" >> \"%s\"'", proc, BLACKLIST_XRECORD);

    int ret = system(cmd);
    if (ret == 0) {
        printf("Successfully added '%s' to xrecord blacklist.\n", proc);
    } else {
        fprintf(stderr, "Failed to add '%s' to xrecord blacklist (code %d)\n", proc, ret);
    }

    notify_notification_close(notification, NULL);
}

void display_notification_screenshot(const char *process_name, const char *title, const char *body)
{
    // 移除重复的 notify_init，移至 main 函数

    NotifyNotification *n = notify_notification_new(title, body, "dialog-warning");
    notify_notification_set_timeout(n, 15000);   // 15 seconds

    if (process_name && process_name[0] != '\0') {
        notify_notification_add_action(n,
            "allow", "Allow",
            (NotifyActionCallback)allow_callback_screenshot,
            g_strdup(process_name),      // pass clean process name
            (GFreeFunc)g_free);

        notify_notification_add_action(n,
            "deny", "Deny",
            (NotifyActionCallback)deny_callback_screenshot,
            NULL, NULL);
    }

    notify_notification_show(n, NULL);
}

void display_notification_screencast(const char *process_name, const char *title, const char *body)
{
    NotifyNotification *n = notify_notification_new(title, body, "dialog-warning");
    notify_notification_set_timeout(n, 15000);

    if (process_name && process_name[0] != '\0') {
        notify_notification_add_action(n,
            "allow", "Allow",
            (NotifyActionCallback)allow_callback_screencast,
            g_strdup(process_name),
            (GFreeFunc)g_free);

        notify_notification_add_action(n,
            "deny", "Deny",
            (NotifyActionCallback)deny_callback_screencast,
            NULL, NULL);
    }

    notify_notification_show(n, NULL);
}

void display_notification_clipboard(const char *process_name, const char *title, const char *body)
{
    NotifyNotification *n = notify_notification_new(title, body, "dialog-warning");
    notify_notification_set_timeout(n, 15000);

    if (process_name && process_name[0] != '\0') {
        notify_notification_add_action(n,
            "allow", "Allow",
            (NotifyActionCallback)allow_callback_clipboard,
            g_strdup(process_name),
            (GFreeFunc)g_free);

        notify_notification_add_action(n,
            "deny", "Deny",
            (NotifyActionCallback)deny_callback_clipboard,
            NULL, NULL);
    }

    notify_notification_show(n, NULL);
}

void display_notification_xrecord(const char *process_name, const char *title, const char *body)
{
    NotifyNotification *n = notify_notification_new(title, body, "dialog-warning");
    notify_notification_set_timeout(n, 15000);

    if (process_name && process_name[0] != '\0') {
        notify_notification_add_action(n,
            "allow", "Allow",
            (NotifyActionCallback)allow_callback_xrecord,
            g_strdup(process_name),
            (GFreeFunc)g_free);

        notify_notification_add_action(n,
            "deny", "Deny",
            (NotifyActionCallback)deny_callback_xrecord,
            NULL, NULL);
    }

    notify_notification_show(n, NULL);
}

int main() {
    DBusConnection *conn;
    DBusError err;

    if (!notify_init("XSM-Agent")) {
        fprintf(stderr, "Failed to initialize libnotify.\n");
        return 1;
    }

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
        dbus_error_free(&err);
        return 1;
    }

    printf("XSM Agent listening for security signals...\n");

    while (1) {
        while (g_main_context_iteration(NULL, FALSE));

        dbus_connection_read_write(conn, 0);
        DBusMessage *msg = dbus_connection_pop_message(conn);

        if (msg == NULL) {
            usleep(100000); // Sleep 100ms
            continue;
        }

        // Check if the message is our specific signal
        if (dbus_message_is_signal(msg, "org.xsm.SecurityInterface", "ViolationDetected")) {
            char *process_name = NULL;
            char *full_message = NULL;

            dbus_int16_t idx = -1;

            dbus_error_init(&err);

            if (dbus_message_get_args(msg, &err,
                                      DBUS_TYPE_INT16, &idx,
                                      DBUS_TYPE_STRING, &process_name,
                                      DBUS_TYPE_STRING, &full_message,
                                      DBUS_TYPE_INVALID)) {

                printf("Security violation received - Process: '%s' | Message: %s | Code: %d\n",
                       process_name ? process_name : "(null)",
                       full_message ? full_message : "(null)",
                       idx);

                if (idx == LOG_SCREENSHOT)
                    display_notification_screenshot(process_name, full_message, "");
                else if (idx == LOG_SCREENCAST)
                    display_notification_screencast(process_name, full_message, "");
                else if (idx == LOG_XRECORD)
                    display_notification_xrecord(process_name, full_message, "");
                else if (idx == LOG_CLIPBOARD)
                    display_notification_clipboard(process_name, full_message, "");

            } else {
                fprintf(stderr, "Failed to parse D-Bus signal arguments: %s\n", err.message);
                dbus_error_free(&err);
            }
        }
        dbus_message_unref(msg);
    }

    notify_uninit();
    return 0;
}
