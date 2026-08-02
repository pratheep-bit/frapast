doc_events = {
    "Attendance": {
        "on_submit": "app_one.handlers.submit_attendance",
        "on_cancel": ["app_one.handlers.cancel_attendance"],
    }
}

permission_query_conditions = {
    "Attendance": "app_one.permissions.attendance_query"
}

has_permission = {
    "Attendance": "app_one.permissions.has_attendance_permission"
}
