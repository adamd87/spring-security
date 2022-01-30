package pl.adamd.springsecurity.security;

enum ApplicationUserPermission {

    USER_READ("user:read"),
    USER_WRITE("user:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

    private final String permission;

    ApplicationUserPermission(final String permission) {
        this.permission = permission;
    }

    String getPermission() {
        return permission;
    }
}
