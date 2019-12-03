package com.jwt.security.system.enums;

public enum UserStatus {
    CAN_USE("can use in system"),
    CAN_NOT_USE("can not user in system");

    private String status;

    UserStatus(String status) {
        this.status = status;
    }

    public String getName() {
        return this.getName();
    }

    public static UserStatus fromRole(String status) {
        for (UserStatus type : UserStatus.values()) {
            if (type.getName().equals(status)) {
                return type;
            }
        }
        return null;
    }

}
